use super::*;
use crate::RuleContext;
use sha2::{Digest, Sha256};
use signal_event::lookup_attribute_path;
use signal_findings::DetectionSeverity;
use std::collections::{BTreeMap, BTreeSet};

fn value<'a>(input: &'a Input<'_>, path: &str) -> Option<&'a serde_json::Value> {
    lookup_attribute_path(&input.event.attributes, path)
}
fn text<'a>(input: &'a Input<'_>, path: &str) -> Result<&'a str, Gap> {
    value(input, path)
        .and_then(serde_json::Value::as_str)
        .filter(|s| identity(s))
        .ok_or(Gap::MissingSourceField)
}
fn optional<'a>(input: &'a Input<'_>, path: &str) -> Result<Option<&'a str>, Gap> {
    match value(input, path) {
        None => Ok(None),
        Some(_) => text(input, path).map(Some),
    }
}
fn number(input: &Input<'_>, path: &str) -> Result<u64, Gap> {
    value(input, path)
        .and_then(serde_json::Value::as_u64)
        .ok_or(Gap::MissingSourceField)
}
fn join(parts: &[&str]) -> String {
    parts
        .iter()
        .map(|part| format!("{}:{part}", part.len()))
        .collect()
}

/// Projection only: callers still need fresh authenticated source/state checks.
/// A false applicability flag never attests clean source coverage.
pub fn query(input: &Input<'_>, rule: Detection, host: &HostContext) -> Result<Query, Gap> {
    if !host_valid(host) {
        return Err(Gap::HostUnverified);
    }
    if rule == Detection::D12 {
        return Err(Gap::DeferredDatabaseSource);
    }
    if input.event.source.source_type != host.source_type
        || input.event.source.name != host.source_name
    {
        return Err(Gap::SourceMismatch);
    }
    let mut q = Query {
        applicable: false,
        scope: host.scope.clone(),
        actor: String::new(),
        locator: String::new(),
        native_target: None,
        change: String::new(),
        action: String::new(),
        outcome: String::new(),
        namespace: String::new(),
        name: String::new(),
        resource: String::new(),
        verb: String::new(),
        process: None,
    };
    match (&host.scope, rule) {
        (Scope::Aws { account }, Detection::D04 | Detection::D06) => {
            if text(input, "aws.cloudtrail.recipient_account_id")? != account {
                return Err(Gap::SourceMismatch);
            }
            let action = text(input, "security.action")?;
            let expected = if rule == Detection::D04 {
                "credential.create"
            } else {
                "iam.permissions.change"
            };
            if action != expected {
                return Ok(q);
            }
            if text(input, "normalizer.id")? != "cloudtrail-state-management"
                || text(input, "normalizer.revision")? != "v1"
            {
                return Err(Gap::UnsupportedSource);
            }
            if value(input, "aws.cloudtrail.iam.identity_complete")
                .and_then(serde_json::Value::as_bool)
                != Some(true)
            {
                return Err(Gap::MissingSourceField);
            }
            q.actor = text(input, "aws.cloudtrail.iam.actor_principal_id")?.into();
            let kind = text(input, "aws.cloudtrail.iam.target_kind")?;
            if !["user", "role"].contains(&kind) {
                return Err(Gap::UnsupportedSource);
            }
            q.name = text(input, "aws.cloudtrail.iam.target_name")?.into();
            q.locator = join(&[kind, &q.name]);
            q.native_target = optional(input, "aws.cloudtrail.iam.target_id")?.map(String::from);
            q.change = text(input, "aws.cloudtrail.event_id")?.into();
            q.action = action.into();
            q.outcome = text(input, "security.outcome")?.into();
        }
        (Scope::Kubernetes { cluster }, Detection::D08 | Detection::D09) => {
            if text(input, "kubernetes.cluster")? != cluster {
                return Err(Gap::SourceMismatch);
            }
            let action = text(input, "security.action")?;
            if action
                != if rule == Detection::D08 {
                    "k8s.rbac.change"
                } else {
                    "k8s.exec"
                }
            {
                return Ok(q);
            }
            if text(input, "kubernetes.state_profile_revision")? != "v1" {
                return Err(Gap::UnsupportedSource);
            }
            let actor = if value(input, "kubernetes.impersonated_user").is_some() {
                if host.impersonation == Impersonation::Reject {
                    return Err(Gap::UnsupportedSemantics);
                }
                "kubernetes.impersonated_user"
            } else {
                "kubernetes.user"
            };
            let username = text(input, &format!("{actor}.username"))?;
            let uid = optional(input, &format!("{actor}.uid"))?.unwrap_or("");
            q.actor = join(&[uid, username]);
            q.resource = text(input, "kubernetes.object.resource")?.into();
            q.name = text(input, "kubernetes.object.name")?.into();
            q.namespace = value(input, "kubernetes.object.namespace")
                .map(|v| v.as_str().ok_or(Gap::MissingSourceField))
                .transpose()?
                .unwrap_or("")
                .into();
            if q.namespace.len() > 1024 {
                return Err(Gap::MissingSourceField);
            }
            q.locator = join(&[&q.resource, &q.namespace, &q.name]);
            q.native_target = optional(input, "kubernetes.object.uid")?.map(String::from);
            q.change = join(&[
                text(input, "kubernetes.audit_id")?,
                text(input, "kubernetes.stage")?,
            ]);
            q.verb = text(input, "kubernetes.verb")?.into();
            q.action = action.into();
            q.outcome = text(input, "security.outcome")?.into();
            if rule == Detection::D09
                && q.outcome == "success"
                && value(input, "kubernetes.exec_session_accepted")
                    .and_then(serde_json::Value::as_bool)
                    != Some(true)
            {
                return Err(Gap::MissingSourceField);
            }
        }
        (
            Scope::Host {
                host: expected,
                boot,
            },
            Detection::D13,
        ) => {
            if text(input, "process.host_id")? != expected
                || text(input, "process.boot_id")? != boot
            {
                return Err(Gap::SourceMismatch);
            }
            if text(input, "runtime.kind")? != "execution" {
                return Ok(q);
            }
            if text(input, "evidence.profile")? != "falco-syscall-metadata-v1"
                || !["execve", "execveat"].contains(&text(input, "runtime.syscall")?)
            {
                return Err(Gap::UnsupportedSource);
            }
            let pid = number(input, "process.pid")?;
            let start = number(input, "process.start_epoch_ns")?;
            let seq = number(input, "producer.sequence")?;
            if pid == 0 || pid > i32::MAX as u64 || start == 0 {
                return Err(Gap::MissingSourceField);
            }
            q.actor = join(&[expected, boot, &pid.to_string(), &start.to_string()]);
            q.locator = join(&[&q.actor, text(input, "process.executable")?]);
            q.change = join(&[
                &seq.to_string(),
                text(input, "runtime.syscall")?,
                &input.event.timestamp.to_rfc3339(),
            ]);
            q.action = "host.exec".into();
            q.outcome = text(input, "runtime.outcome")?.into();
            q.process = Some(ProcessIdentity {
                host: expected.clone(),
                boot: boot.clone(),
                pid,
                start_epoch_ns: start,
                execution_sequence: seq,
            });
        }
        _ => return Ok(q),
    }
    if !["success", "failure"].contains(&q.outcome.as_str()) {
        return Err(Gap::MissingSourceField);
    }
    q.applicable = true;
    Ok(q)
}

pub(crate) fn host_valid(host: &HostContext) -> bool {
    host.source_binding != [0; 32]
        && host.policy_config_sha256 != [0; 32]
        && host.authority_keys_sha256 != [0; 32]
        && match host.scope {
            Scope::Aws { .. } => host.source_type == "cloudtrail",
            Scope::Kubernetes { .. } => host.source_type == "kubernetes.audit",
            Scope::Host { .. } => true,
        }
        && scope_valid(&host.scope)
        && identity(&host.source_type)
        && host.source_name.as_ref().is_none_or(|s| identity(s))
        && [
            &host.policy_revision,
            &host.source_config_revision,
            &host.state_authority_revision,
            &host.verification_reference,
        ]
        .iter()
        .all(|s| identity(s))
}

fn count<T>(items: &[T], maximum: usize) -> Result<(), Error> {
    if items.len() > maximum {
        Err(Error::Capacity)
    } else {
        Ok(())
    }
}
fn id(value: &str) -> Result<(), Error> {
    if identity(value) {
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}
fn subject(value: &Subject) -> Result<(), Error> {
    match value {
        Subject::User { name } | Subject::Group { name } => id(name),
        Subject::ServiceAccount { namespace, name } => {
            id(namespace)?;
            id(name)
        }
    }
}
fn permission(value: &Permission) -> Result<(), Error> {
    match value {
        Permission::Iam {
            principal,
            action,
            resource,
        } => {
            id(principal)?;
            id(action)?;
            id(resource)
        }
        Permission::Rbac {
            subject: s,
            api_group,
            resource,
            namespace,
            resource_name,
            verb,
        } => {
            subject(s)?;
            if !api_group.is_empty() {
                id(api_group)?;
            }
            id(resource)?;
            id(verb)?;
            for item in [namespace, resource_name].into_iter().flatten() {
                id(item)?;
            }
            Ok(())
        }
    }
}
fn approvals(items: &[Approval], context: &RuleContext) -> Result<(), Error> {
    count(items, MAX_ENTRIES)?;
    let mut ids = BTreeSet::new();
    for a in items {
        check(context)?;
        for v in [&a.id, &a.actor, &a.target, &a.action] {
            id(v)?;
        }
        if !a.change.is_empty() {
            id(&a.change)?;
        }
        if !ids.insert(&a.id) || a.validity.from >= a.validity.until {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}
fn iam(view: &IamView, context: &RuleContext) -> Result<(), Error> {
    id(&view.revision)?;
    id(&view.principal_id)?;
    count(&view.unsupported, 16)?;
    count(&view.grants, MAX_GRANTS)?;
    for grant in &view.grants {
        check(context)?;
        permission(grant)?;
    }
    Ok(())
}
fn rbac(view: &RbacView, context: &RuleContext) -> Result<(), Error> {
    id(&view.revision)?;
    count(&view.unsupported, 16)?;
    count(&view.namespaces, MAX_ENTRIES)?;
    count(&view.roles, MAX_ENTRIES)?;
    count(&view.bindings, MAX_ENTRIES)?;
    for ns in &view.namespaces {
        check(context)?;
        id(ns)?;
    }
    for role in &view.roles {
        check(context)?;
        for s in [&role.uid, &role.revision, &role.name] {
            id(s)?;
        }
        if let Some(ns) = &role.namespace {
            id(ns)?;
        }
        count(&role.grants, MAX_GRANTS)?;
        for grant in &role.grants {
            check(context)?;
            if !grant.api_group.is_empty() {
                id(&grant.api_group)?;
            }
            id(&grant.resource)?;
            id(&grant.verb)?;
            if let Some(n) = &grant.resource_name {
                id(n)?;
            }
        }
    }
    for binding in &view.bindings {
        check(context)?;
        for s in [
            &binding.uid,
            &binding.revision,
            &binding.name,
            &binding.role_name,
        ] {
            id(s)?;
        }
        if let Some(ns) = &binding.namespace {
            id(ns)?;
        }
        count(&binding.subjects, MAX_GRANTS)?;
        for s in &binding.subjects {
            subject(s)?;
        }
    }
    Ok(())
}
pub(crate) fn snapshot_budget(s: &Snapshot, context: &RuleContext) -> Result<(), Error> {
    check(context)?;
    for v in [&s.authority_revision, &s.revision, &s.resolved_target] {
        id(v)?;
    }
    for key in [&s.actor, &s.locator, &s.change] {
        if key.is_empty() || key.len() > 8192 || key.chars().any(char::is_control) {
            return Err(Error::Invalid);
        }
    }
    id(&s.policy_revision)?;
    id(&s.source_config_revision)?;
    if !scope_valid(&s.scope) {
        return Err(Error::Invalid);
    }
    match &s.data {
        Data::Credentials { approvals: a } => approvals(a, context)?,
        Data::Iam {
            before,
            after,
            approved,
        } => {
            iam(before, context)?;
            iam(after, context)?;
            count(approved, MAX_GRANTS)?;
            for g in approved {
                permission(g)?;
            }
        }
        Data::Rbac {
            before,
            after,
            approved,
        } => {
            rbac(before, context)?;
            rbac(after, context)?;
            count(approved, MAX_GRANTS)?;
            for g in approved {
                permission(g)?;
            }
        }
        Data::Workload {
            history,
            approvals: a,
        } => {
            count(history, MAX_ENTRIES)?;
            approvals(a, context)?;
            for w in history {
                check(context)?;
                for v in [&w.uid, &w.namespace, &w.name, &w.revision] {
                    id(v)?;
                }
                if w.validity.from >= w.validity.until {
                    return Err(Error::Invalid);
                }
            }
        }
        Data::Process { history } => {
            count(history, MAX_ENTRIES)?;
            for p in history {
                check(context)?;
                for v in [&p.host, &p.boot, &p.revision] {
                    id(v)?;
                }
                if p.validity.from >= p.validity.until {
                    return Err(Error::Invalid);
                }
            }
        }
    }
    input::encode(s, MAX_STATE_BYTES, context)?;
    Ok(())
}
fn literal(s: &str, empty: bool) -> bool {
    (empty || !s.is_empty())
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && !b"*?\\\"${}".contains(&b))
}
fn supported(permission: &Permission) -> bool {
    match permission {
        Permission::Iam {
            principal,
            action,
            resource,
        } => [principal, action, resource]
            .iter()
            .all(|s| literal(s, false)),
        Permission::Rbac {
            subject,
            api_group,
            resource,
            namespace,
            resource_name,
            verb,
        } => {
            !matches!(subject, Subject::Group { .. })
                && literal(api_group, true)
                && literal(resource, false)
                && literal(verb, false)
                && !(resource_name.is_some()
                    && (verb == "deletecollection" || verb == "create" && !resource.contains('/')))
                && [namespace, resource_name]
                    .into_iter()
                    .flatten()
                    .all(|s| literal(s, false))
        }
    }
}

fn approved(entries: &[Approval], q: &Query, target: &str, at: DateTime<Utc>) -> Vec<String> {
    entries
        .iter()
        .filter(|a| {
            a.actor == q.actor
                && a.target == target
                && a.action == q.action
                && (a.change.is_empty() || a.change == q.change)
                && a.validity.contains(at)
        })
        .map(|a| a.id.clone())
        .collect()
}
fn covers(old: &Permission, new: &Permission) -> bool {
    match (old, new) {
        (
            Permission::Iam {
                principal: a,
                action: b,
                resource: c,
            },
            Permission::Iam {
                principal: x,
                action: y,
                resource: z,
            },
        ) => a == x && b.eq_ignore_ascii_case(y) && c == z,
        (
            Permission::Rbac {
                subject: a,
                api_group: b,
                resource: c,
                namespace: d,
                resource_name: e,
                verb: f,
            },
            Permission::Rbac {
                subject: u,
                api_group: v,
                resource: w,
                namespace: x,
                resource_name: y,
                verb: z,
            },
        ) => a == u && b == v && c == w && d == x && f == z && (e.is_none() || e == y),
        _ => false,
    }
}
fn delta(
    before: BTreeSet<Permission>,
    after: BTreeSet<Permission>,
    approved: &[Permission],
) -> Result<Vec<Permission>, Gap> {
    if before
        .iter()
        .chain(&after)
        .chain(approved)
        .any(|g| !supported(g))
    {
        return Err(Gap::UnsupportedSemantics);
    }
    Ok(after
        .iter()
        .filter(|g| {
            !before.iter().any(|old| covers(old, g)) && !approved.iter().any(|a| covers(a, g))
        })
        .cloned()
        .collect())
}

fn expand(
    view: &RbacView,
    context: &RuleContext,
) -> Result<Result<BTreeSet<Permission>, Gap>, Error> {
    if !view.complete || !view.unsupported.is_empty() || view.namespaces.is_empty() {
        return Ok(Err(Gap::UnsupportedSemantics));
    }
    let namespaces: BTreeSet<_> = view.namespaces.iter().collect();
    if namespaces.len() != view.namespaces.len() {
        return Ok(Err(Gap::AmbiguousHistory));
    }
    let mut roles = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for role in &view.roles {
        check(context)?;
        if !ids.insert(&role.uid)
            || roles.insert((&role.namespace, &role.name), role).is_some()
            || role
                .namespace
                .as_ref()
                .is_some_and(|n| !namespaces.contains(n))
        {
            return Ok(Err(Gap::AmbiguousHistory));
        }
    }
    let mut binding_names = BTreeSet::new();
    let mut output = BTreeSet::new();
    let mut visits = 0usize;
    for binding in &view.bindings {
        check(context)?;
        if !ids.insert(&binding.uid) || !binding_names.insert((&binding.namespace, &binding.name)) {
            return Ok(Err(Gap::AmbiguousHistory));
        }
        if binding.namespace.is_none() && !binding.cluster_role {
            return Ok(Err(Gap::UnsupportedSemantics));
        }
        if binding
            .namespace
            .as_ref()
            .is_some_and(|n| !namespaces.contains(n))
        {
            return Ok(Err(Gap::UnsupportedSemantics));
        }
        let ns = if binding.cluster_role {
            None
        } else {
            binding.namespace.clone()
        };
        let Some(role) = roles.get(&(&ns, &binding.role_name)) else {
            return Ok(Err(Gap::UnsupportedSemantics));
        };
        for template in &role.grants {
            if !template.namespaced && binding.namespace.is_some() {
                return Ok(Err(Gap::UnsupportedSemantics));
            }
            let scopes: Vec<Option<&String>> = if !template.namespaced {
                vec![None]
            } else if let Some(ns) = &binding.namespace {
                vec![Some(ns)]
            } else {
                view.namespaces.iter().map(Some).collect()
            };
            for subject in &binding.subjects {
                for ns in &scopes {
                    check(context)?;
                    visits += 1;
                    if visits > 4096 {
                        return Err(Error::Capacity);
                    }
                    let grant = Permission::Rbac {
                        subject: subject.clone(),
                        api_group: template.api_group.clone(),
                        resource: template.resource.clone(),
                        namespace: ns.map(String::to_owned),
                        resource_name: template.resource_name.clone(),
                        verb: template.verb.clone(),
                    };
                    if !supported(&grant) {
                        return Ok(Err(Gap::UnsupportedSemantics));
                    }
                    output.insert(grant);
                    if output.len() > MAX_GRANTS {
                        return Err(Error::Capacity);
                    }
                }
            }
        }
    }
    Ok(Ok(output))
}

fn only_changed(before: &RbacView, after: &RbacView, target: &str, q: &Query) -> bool {
    if before.namespaces != after.namespaces || before.revision == after.revision {
        return false;
    }
    let roles = |v: &RbacView| {
        v.roles
            .iter()
            .filter(|r| r.uid != target)
            .map(|r| (r.uid.clone(), r.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let bindings = |v: &RbacView| {
        v.bindings
            .iter()
            .filter(|b| b.uid != target)
            .map(|b| (b.uid.clone(), b.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    if roles(before) != roles(after) || bindings(before) != bindings(after) {
        return false;
    }
    let location = |v: &RbacView| -> bool {
        if ["roles", "clusterroles"].contains(&q.resource.as_str()) {
            v.roles.iter().any(|r| {
                r.uid == target
                    && r.name == q.name
                    && r.namespace.as_deref().unwrap_or("") == q.namespace
                    && (r.namespace.is_some() == (q.resource == "roles"))
            })
        } else {
            v.bindings.iter().any(|b| {
                b.uid == target
                    && b.name == q.name
                    && b.namespace.as_deref().unwrap_or("") == q.namespace
                    && (b.namespace.is_some() == (q.resource == "rolebindings"))
            })
        }
    };
    if ["update", "patch"].contains(&q.verb.as_str())
        && ["rolebindings", "clusterrolebindings"].contains(&q.resource.as_str())
    {
        let old = before.bindings.iter().find(|b| b.uid == target);
        let new = after.bindings.iter().find(|b| b.uid == target);
        if old
            .zip(new)
            .is_none_or(|(a, b)| a.role_name != b.role_name || a.cluster_role != b.cluster_role)
        {
            return false;
        }
    }
    match q.verb.as_str() {
        "create" => {
            !before.roles.iter().any(|r| r.uid == target)
                && !before.bindings.iter().any(|b| b.uid == target)
                && location(after)
        }
        "delete" => {
            location(before)
                && !after.roles.iter().any(|r| r.uid == target)
                && !after.bindings.iter().any(|b| b.uid == target)
        }
        "update" | "patch" => location(before) && location(after),
        _ => false,
    }
}

pub fn assess(
    input: &Input<'_>,
    rule: Detection,
    state: Option<&Snapshot>,
    host: &HostContext,
    context: &RuleContext,
) -> Result<Decision, Error> {
    check(context)?;
    if !host_valid(host) {
        return Err(Error::Invalid);
    }
    let mut decision = Decision {
        schema_version: 1,
        detector_revision: "scoped-state-v1",
        rule,
        event_id: input.event.id,
        input_sha256: input.sha256,
        state_sha256: state.map(|s| state_digest(s, context)).transpose()?,
        host_evidence: host.retained(),
        source_binding: host.source_binding,
        source_config_revision: host.source_config_revision.clone(),
        policy_revision: host.policy_revision.clone(),
        policy_config_sha256: host.policy_config_sha256,
        authority_keys_sha256: host.authority_keys_sha256,
        state_revision: None,
        status: Status::Indeterminate,
        applicable: true,
        coverage_gap: true,
        gap: None,
        target: None,
        approval_ids: vec![],
        added_permissions: vec![],
        finding: None,
        seal: [0; 32],
        original_context: context.clone(),
    };
    let mut gap = if rule == Detection::D12 {
        Some(Gap::DeferredDatabaseSource)
    } else if !host.ready
        || host.verified_at > host.now
        || host.verified_until <= host.now
        || host.verified_at >= host.verified_until
        || input.event.observed_at > host.now
    {
        Some(Gap::HostUnverified)
    } else {
        None
    };
    if gap.is_none() {
        match query(input, rule, host) {
            Err(reason) => gap = Some(reason),
            Ok(q) if !q.applicable => {
                decision.applicable = false;
                decision.status = Status::NoMatch;
            }
            Ok(q) if q.outcome == "failure" => decision.status = Status::NoMatch,
            Ok(q) => match state {
                None => gap = Some(Gap::StateMissing),
                Some(s) => {
                    snapshot_budget(s, context)?;
                    if s.schema_version != 1
                        || s.rule != rule
                        || s.source_binding != host.source_binding
                        || s.input_sha256 != input.sha256
                        || s.scope != host.scope
                        || s.authority_revision != host.state_authority_revision
                        || s.policy_revision != host.policy_revision
                        || s.policy_config_sha256 != host.policy_config_sha256
                        || s.authority_keys_sha256 != host.authority_keys_sha256
                        || s.source_config_revision != host.source_config_revision
                        || s.actor != q.actor
                        || s.locator != q.locator
                        || s.change != q.change
                        || q.native_target
                            .as_ref()
                            .is_some_and(|uid| uid != &s.resolved_target)
                    {
                        gap = Some(Gap::StateMismatch);
                    } else if s.observed_at > host.now
                        || s.expires_at <= host.now
                        || s.expires_at <= s.observed_at
                        || !s.validity.contains(input.event.timestamp)
                    {
                        gap = Some(Gap::StateStale);
                    } else if !s.complete {
                        gap = Some(Gap::IncompleteInventory);
                    } else {
                        decision.state_revision = Some(s.revision.clone());
                        decision.target = Some(s.resolved_target.clone());
                        let at = input.event.timestamp;
                        match (rule,&s.data) {
                                (Detection::D04,Data::Credentials {approvals:entries})=>{
                                    decision.approval_ids=approved(entries,&q,&s.resolved_target,at);
                                    decision.status=if decision.approval_ids.is_empty(){Status::Match}else{Status::NoMatch};
                                }
                                (Detection::D06,Data::Iam {before,after,approved})=>{
                                    if !before.complete||!after.complete||!before.unsupported.is_empty()||!after.unsupported.is_empty()
                                        || before.principal_id!=s.resolved_target||after.principal_id!=s.resolved_target||before.revision==after.revision
                                        || before.grants.iter().chain(&after.grants).chain(approved).any(|g|!matches!(g,Permission::Iam {principal,..} if principal==&s.resolved_target)) {gap=Some(Gap::UnsupportedSemantics);}
                                    else {match delta(before.grants.iter().cloned().collect(),after.grants.iter().cloned().collect(),approved){Err(g)=>gap=Some(g),Ok(added)=>{decision.status=if added.is_empty(){Status::NoMatch}else{Status::Match};decision.added_permissions=added;}}}
                                }
                                (Detection::D08,Data::Rbac {before,after,approved})=>{
                                    if !only_changed(before,after,&s.resolved_target,&q) || approved.iter().any(|g|!matches!(g,Permission::Rbac {..})){gap=Some(Gap::StateMismatch);}
                                    else {match (expand(before,context)?,expand(after,context)?){(Ok(a),Ok(b))=>match delta(a,b,approved){Err(g)=>gap=Some(g),Ok(added)=>{decision.status=if added.is_empty(){Status::NoMatch}else{Status::Match};decision.added_permissions=added;}},(Err(g),_)|(_,Err(g))=>gap=Some(g)}}
                                }
                                (Detection::D09,Data::Workload {history,approvals:entries})=>{
                                    let rows:Vec<_>=history.iter().filter(|w|w.namespace==q.namespace&&w.name==q.name&&w.validity.contains(at)
                                        && q.native_target.as_ref().is_none_or(|uid|uid==&w.uid)).collect();
                                    if rows.len()!=1{gap=Some(if rows.is_empty(){Gap::StateMissing}else{Gap::AmbiguousHistory});}
                                    else if rows[0].uid!=s.resolved_target{gap=Some(Gap::StateMismatch);}
                                    else if !rows[0].sensitive{decision.status=Status::NoMatch;}
                                    else {decision.approval_ids=approved(entries,&q,&rows[0].uid,at);decision.status=if decision.approval_ids.is_empty(){Status::Match}else{Status::NoMatch};}
                                }
                                (Detection::D13,Data::Process {history})=>{
                                    let key=q.process.as_ref().ok_or(Error::Invalid)?;
                                    let rows:Vec<_>=history.iter().filter(|p|p.host==key.host&&p.boot==key.boot&&p.pid==key.pid&&p.start_epoch_ns==key.start_epoch_ns
                                        && p.execution_sequence==key.execution_sequence&&p.validity.contains(at)).collect();
                                    if rows.len()!=1{gap=Some(if rows.is_empty(){Gap::StateMissing}else{Gap::AmbiguousHistory});}
                                    else {
                                        let p=rows[0];let digest:String=p.executable_sha256.iter().map(|b|format!("{b:02x}")).collect();
                                        if !p.provenance_verified||p.executable_sha256==[0;32]{gap=Some(Gap::UnsupportedSemantics);}
                                        else if digest!=s.resolved_target{gap=Some(Gap::StateMismatch);}
                                        else {decision.status=if p.privileged&&!p.approved{Status::Match}else{Status::NoMatch};}
                                    }
                                }
                                _=>gap=Some(Gap::UnsupportedSemantics),
                            }
                    }
                }
            },
        }
    }
    decision.gap = gap;
    decision.coverage_gap = gap.is_some();
    if gap.is_some() {
        decision.status = Status::Indeterminate;
        decision.approval_ids.clear();
        decision.added_permissions.clear();
    }
    if decision.status == Status::Match {
        decision.finding = Some(
            Finding::for_event(
                rule.id(),
                input.event,
                DetectionSeverity::High,
                "Scoped state requires investigation",
            )
            .map_err(|_| Error::Invalid)?,
        );
    }
    decision.seal = decision_digest(&decision, context)?;
    check(context)?;
    Ok(decision)
}

pub(crate) fn state_digest(state: &Snapshot, context: &RuleContext) -> Result<[u8; 32], Error> {
    snapshot_budget(state, context)?;
    let bytes = input::encode(state, MAX_STATE_BYTES, context)?;
    let mut hash = Sha256::new();
    hash.update(b"PLATFORM::SIGNAL/scoped-state/evidence/v1\0");
    hash.update(bytes);
    check(context)?;
    Ok(hash.finalize().into())
}
pub(crate) fn decision_digest(
    decision: &Decision,
    context: &RuleContext,
) -> Result<[u8; 32], Error> {
    let bytes = input::encode(decision, MAX_OUTPUT_BYTES, context)?;
    let mut hash = Sha256::new();
    hash.update(b"PLATFORM::SIGNAL/scoped-state/decision/v1\0");
    hash.update(bytes);
    check(context)?;
    Ok(hash.finalize().into())
}
