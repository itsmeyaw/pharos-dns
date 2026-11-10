use std::{fs, path::Path};

fn parse_quota(v2: Option<&str>, quota: Option<&str>, period: Option<&str>) -> Option<usize> {
    let (quota, period) = if let Some(v2) = v2 {
        let mut fields = v2.split_whitespace();
        (fields.next()?, fields.next()?)
    } else {
        (quota?.trim(), period?.trim())
    };
    let quota: usize = quota.parse().ok()?;
    let period: usize = period.parse().ok()?;
    if quota == 0 || period == 0 {
        return None;
    }
    Some(quota.div_ceil(period))
}

fn cgroup_path(groups: &str, v2: bool) -> Option<&str> {
    groups.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let path = fields.next()?;
        if (v2 && controllers.is_empty()) || (!v2 && controllers.split(',').any(|c| c == "cpu")) {
            Some(path)
        } else {
            None
        }
    })
}

fn hierarchy_quota(base: &Path, group: &str, v2: bool) -> Option<usize> {
    let mut path = base.join(group.trim_start_matches('/'));
    let mut limit: Option<usize> = None;
    loop {
        let quota = if v2 {
            let v2 = fs::read_to_string(path.join("cpu.max")).ok();
            parse_quota(v2.as_deref(), None, None)
        } else {
            let quota = fs::read_to_string(path.join("cpu.cfs_quota_us")).ok();
            let period = fs::read_to_string(path.join("cpu.cfs_period_us")).ok();
            parse_quota(None, quota.as_deref(), period.as_deref())
        };
        if let Some(quota) = quota {
            limit = Some(limit.map_or(quota, |old| old.min(quota)));
        }
        if path == base || !path.pop() {
            break;
        }
    }
    limit
}

pub(crate) fn worker_count() -> usize {
    let groups = fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let v2_base = Path::new("/sys/fs/cgroup");
    let quota = if v2_base.join("cpu.max").exists() {
        hierarchy_quota(v2_base, cgroup_path(&groups, true).unwrap_or("/"), true)
    } else {
        ["/sys/fs/cgroup/cpu", "/sys/fs/cgroup/cpu,cpuacct"]
            .iter()
            .find_map(|base| {
                let base = Path::new(base);
                if base.exists() {
                    hierarchy_quota(base, cgroup_path(&groups, false).unwrap_or("/"), false)
                } else {
                    None
                }
            })
    };
    quota.unwrap_or_else(|| {
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
    })
}

#[cfg(test)]
mod tests {
    use super::{cgroup_path, parse_quota};

    #[test]
    fn finds_the_current_cpu_cgroup() {
        let groups = "0::/user.slice/service\n4:memory:/other\n5:cpu,cpuacct:/team/service\n";
        assert_eq!(cgroup_path(groups, true), Some("/user.slice/service"));
        assert_eq!(cgroup_path(groups, false), Some("/team/service"));
        assert_eq!(cgroup_path("4:memory:/other\n", false), None);
    }

    #[test]
    fn parses_cgroup_v2_and_v1_quotas() {
        assert_eq!(parse_quota(Some("150000 100000\n"), None, None), Some(2));
        assert_eq!(
            parse_quota(None, Some("200000\n"), Some("100000\n")),
            Some(2)
        );
        assert_eq!(parse_quota(Some("1 100000"), None, None), Some(1));
    }

    #[test]
    fn unlimited_invalid_and_missing_quotas_fall_back() {
        assert_eq!(parse_quota(Some("max 100000"), None, None), None);
        assert_eq!(parse_quota(None, Some("-1"), Some("100000")), None);
        assert_eq!(parse_quota(None, None, None), None);
        assert_eq!(parse_quota(Some("10 0"), None, None), None);
        assert_eq!(parse_quota(Some("bad"), None, None), None);
    }
}
