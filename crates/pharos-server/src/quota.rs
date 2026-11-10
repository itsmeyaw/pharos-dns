use std::fs;

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
    Some(quota / period + usize::from(quota % period != 0))
}

pub(crate) fn worker_count() -> usize {
    let v2 = fs::read_to_string("/sys/fs/cgroup/cpu.max").ok();
    let quota = fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_quota_us").ok();
    let period = fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_period_us").ok();
    parse_quota(v2.as_deref(), quota.as_deref(), period.as_deref()).unwrap_or_else(|| {
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
    })
}

#[cfg(test)]
mod tests {
    use super::parse_quota;

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
