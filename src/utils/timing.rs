// Timing helpers without external dependencies.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn utc_timestamp_millis() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_timestamp(duration.as_secs(), duration.subsec_millis())
}

pub fn utc_rfc3339() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_rfc3339(duration.as_secs())
}

pub fn parse_ymd_to_timestamp(date_str: &str) -> Option<u64> {
    let parts: Vec<&str> = date_str.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year = parts[0].parse::<i32>().ok()?;
    let month = parts[1].parse::<u32>().ok()?;
    let day = parts[2].parse::<u32>().ok()?;
    let days = days_since_epoch(year, month, day)?;
    Some(days * 86_400)
}

fn format_timestamp(secs: u64, millis: u32) -> String {
    let (year, month, day, hour, minute, second) = split_timestamp(secs);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        year, month, day, hour, minute, second, millis
    )
}

fn format_rfc3339(secs: u64) -> String {
    let (year, month, day, hour, minute, second) = split_timestamp(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn split_timestamp(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let seconds_of_day = (secs % 86_400) as u32;
    let (year, month, day) = ymd_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    (year, month, day, hour, minute, second)
}

fn ymd_from_days(mut days: i64) -> (i32, u32, u32) {
    let mut year = 1970;
    loop {
        let year_days = if is_leap(year) { 366 } else { 365 };
        if days >= year_days {
            days -= year_days;
            year += 1;
        } else {
            break;
        }
    }

    let mut month = 1;
    loop {
        let month_days = days_in_month(year, month);
        if days >= month_days as i64 {
            days -= month_days as i64;
            month += 1;
        } else {
            break;
        }
    }

    let day = (days + 1) as u32;
    (year, month as u32, day)
}

fn days_since_epoch(year: i32, month: u32, day: u32) -> Option<u64> {
    if month == 0 || month > 12 {
        return None;
    }

    let month_days = days_in_month(year, month);
    if day == 0 || day > month_days {
        return None;
    }

    let mut days = 0u64;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }

    for m in 1..month {
        days += days_in_month(year, m) as u64;
    }

    days += (day - 1) as u64;
    Some(days)
}

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(year) {
                29
            } else {
                28
            }
        }
        _ => 30,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ymd_to_timestamp() {
        let ts = parse_ymd_to_timestamp("1970-01-01").unwrap();
        assert_eq!(ts, 0);
    }

    #[test]
    fn test_format_rfc3339() {
        let stamp = format_rfc3339(0);
        assert_eq!(stamp, "1970-01-01T00:00:00Z");
    }
}
