//! Calendar arithmetic (proleptic Gregorian, UTC-agnostic): converting
//! between a date-time and seconds since 1970-01-01. Used by the kernel's
//! RTC clock and by `ledger-tool` to print BOOT record times.
//! Algorithms: Howard Hinnant, "chrono-Compatible Low-Level Date Algorithms".

/// A calendar date and time of day.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateTime {
    pub year: u32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

impl DateTime {
    /// Seconds since 1970-01-01 00:00:00 (for dates from 1970 on).
    pub fn unix_seconds(&self) -> u64 {
        let days = days_from_civil(self.year as i64, self.month as i64, self.day as i64);
        (days * 86400 + self.hour as i64 * 3600 + self.minute as i64 * 60 + self.second as i64) as u64
    }

    pub fn from_unix(t: u64) -> Self {
        let z = (t / 86400) as i64 + 719468;
        let rem = t % 86400;
        let era = if z >= 0 { z } else { z - 146096 } / 146097;
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
        Self {
            year: y as u32,
            month: m as u8,
            day: d as u8,
            hour: (rem / 3600) as u8,
            minute: (rem / 60 % 60) as u8,
            second: (rem % 60) as u8,
        }
    }
}

impl core::fmt::Display for DateTime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dt(year: u32, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> DateTime {
        DateTime { year, month, day, hour, minute, second }
    }

    // Expected values from Python's calendar.timegm.
    #[test]
    fn known_unix_times() {
        assert_eq!(dt(1970, 1, 1, 0, 0, 0).unix_seconds(), 0);
        assert_eq!(dt(2026, 10, 18, 0, 3, 37).unix_seconds(), 1_792_281_817);
        assert_eq!(dt(2024, 2, 29, 23, 59, 59).unix_seconds(), 1_709_251_199);
        assert_eq!(dt(2000, 3, 1, 0, 0, 0).unix_seconds(), 951_868_800);
    }

    #[test]
    fn roundtrip_over_a_range() {
        let mut t = 0u64;
        while t < 4_102_444_800 {
            // 1970..2100, stepping ~13.7 days with an odd remainder
            assert_eq!(DateTime::from_unix(t).unix_seconds(), t, "t = {t}");
            t += 1_183_777;
        }
        assert_eq!(DateTime::from_unix(1_709_251_199), dt(2024, 2, 29, 23, 59, 59));
    }
}
