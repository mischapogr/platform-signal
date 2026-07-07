/* One pure calculation engine shared by the offline browser and build-time Node. */
(() => {
  'use strict';
  const GiB = 1024 ** 3;
  const MiB = 1024 ** 2;
  function tierCost(quantity, tiers) {
    let total = 0, previous = 0;
    for (const [limit, rate] of tiers) {
      const end = limit === null ? Infinity : limit;
      total += Math.max(0, Math.min(quantity, end) - previous) * rate;
      previous = end;
    }
    return total;
  }
  function evaluate(model, input = {}) {
    const o = {...model.defaults, ...input};
    if (![o.traffic, o.searchDays, o.originalDays, o.compression, o.hourlyLabor, o.computeMultiplier].every(v => Number.isFinite(v) && v > 0) || o.compression > 1 || typeof o.sourceDelivery !== 'boolean') throw new Error('Invalid scenario settings');
    const r = model.rates, a = model.assumptions;
    return model.scenarios.map(s => {
      const scope = {...s, dbInstances: s.auroraInstances + s.rdsInstances};
      const sources = a.sourceProfiles.map(p => ({...p, count:scope[p.entity], gbDay:scope[p.entity]*p.gbDayEach*o.traffic, messagesDay:scope[p.entity]*p.gbDayEach*o.traffic*1e9/p.meanBytes}));
      const gbDay = sources.reduce((sum, p) => sum + p.gbDay, 0);
      const messagesDay = sources.reduce((sum, p) => sum + p.messagesDay, 0);
      const sourceGBDay = sources.filter(p => p.delivery === 'cloudwatch').reduce((sum,p)=>sum+p.gbDay,0);
      const normalizedGiB = gbDay*1e9*o.compression*o.searchDays/GiB;
      const originalGiB = gbDay*1e9*a.originalFraction*a.originalCompression*o.originalDays/GiB;
      // Conservative separate-cell storage tiers; payer-level aggregation can lower them.
      const s3 = s.cells*tierCost((normalizedGiB+originalGiB)/s.cells,r.s3Tiers);
      const normObjectsDay = Math.max(gbDay*1e9*o.compression/(a.normalizedObjectMiB*MiB),s.accounts*24*4);
      const originalObjectsDay = Math.max(gbDay*1e9*a.originalFraction*a.originalCompression/(a.originalObjectMiB*MiB),s.accounts*24*2);
      const puts = a.trafficDays*(normObjectsDay*2+originalObjectsDay) + s.accounts*a.computeHours;
      const queryGets = s.accounts*a.queriesPerAccountDay*a.trafficDays*a.filesPerQuery;
      const gets = queryGets + a.trafficDays*(normObjectsDay+originalObjectsDay);
      const kmsRequests = puts+gets;
      const compute = (s.servers+s.collectors)*o.computeMultiplier*a.computeHours*r.ec2Hour;
      const disks = s.ebsGiB*o.computeMultiplier*(r.ebsGiBMonth+a.snapshotFraction*r.snapshotGiBMonth);
      const control = s.controlDBs*(a.computeHours*r.rdsMultiAZHour+s.controlDBGiBEach*r.rdsMultiAZGiBMonth);
      const lcu = Math.max(1,gbDay*1e9*a.trafficDays/GiB/a.computeHours/s.cells);
      const alb = s.cells*a.computeHours*(r.albHour+lcu*r.albLCUHour);
      const endpoint = s.cells*s.azs*a.apiEndpointServices*a.computeHours*r.endpointAZHour+s.cells*a.apiEndpointGiBPerCellMonth*r.endpointGiB;
      const crossAZ = s.azs===1?0:gbDay*1e9*a.trafficDays/GiB*a.crossAZFraction*r.crossAZGiBCombined;
      const requests = puts*r.s3Put+gets*r.s3Get;
      const security = s.keys*r.kmsKeyMonth+kmsRequests*r.kmsRequest+s.secrets*r.secretMonth+s.secrets*a.computeHours*r.secretRequest;
      const transport = a.trafficDays*originalObjectsDay*3*r.sqsRequest;
      const sourceDelivery = o.sourceDelivery?sourceGBDay*1e9/GiB*(a.trafficDays*r.cloudwatchIngestGiB+a.cloudwatchDays*r.cloudwatchStoreGiBMonth):0;
      const components = {compute,disks,control,s3,requests,security,network:alb+endpoint+crossAZ,transport,monitoring:s.monitoringAllowance};
      const directAWS = Object.values(components).reduce((sum,v)=>sum+v,0);
      const totalAWS = directAWS + sourceDelivery;
      const laborHours = [s.platformHours[0]+s.detectionHours[0],s.platformHours[1]+s.detectionHours[1]];
      return {...scope,sources,gbDay,messagesDay,meanBytes:gbDay*1e9/messagesDay,eps:messagesDay/86400,burstEPS:messagesDay/86400*a.burstFactor,normalizedGiB,originalGiB,puts,gets,queryScannedGiB:queryGets*a.queryFileMiB*MiB/GiB,components,directAWS,sourceDelivery,totalAWS,budgetAWS:totalAWS*(1+a.awsBudgetReserve),laborHours,laborUSD: laborHours.map(h=>h*o.hourlyLabor),fte: laborHours.map(h=>h/a.fteHoursMonth),fullyLoaded: laborHours.map(h=>totalAWS+h*o.hourlyLabor),existingEKSControlPlane:s.eks*a.computeHours*r.eksClusterHour,spoolGiB:gbDay*1e9/GiB/6*2};
    });
  }
  const api = {evaluate,tierCost};
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else globalThis.SignalCostModel = api;
})();
