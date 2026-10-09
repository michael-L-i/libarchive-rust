/*
 * This code is in the public domain and has no copyright.
 *
 * This is a plain C recursive-descent translation of an old
 * public-domain YACC grammar that has been used for parsing dates in
 * very many open-source projects.
 *
 * Since the original authors were generous enough to donate their
 * work to the public domain, I feel compelled to match their
 * generosity.
 *
 * Tim Kientzle, February 2009.
 */

/*
 * Header comment from original getdate.y:
 */

/*
**  Originally written by Steven M. Bellovin <smb@research.att.com> while
**  at the University of North Carolina at Chapel Hill.  Later tweaked by
**  a couple of people on Usenet.  Completely overhauled by Rich $alz
**  <rsalz@bbn.com> and Jim Berets <jberets@bbn.com> in August, 1990;
**
**  This grammar has 10 shift/reduce conflicts.
**
**  This code is in the public domain and has no copyright.
*/

// Ported from libarchive/archive_parse_date.c.

use crate::ffi::sys;
const AGO: i32 = 260;
const DAY: i32 = 261;
const DAYZONE: i32 = 262;
const AMPM: i32 = 263;
const MONTH: i32 = 264;
const MONTH_UNIT: i32 = 265;
const SEC_UNIT: i32 = 266;
const NUMBER: i32 = 267;
const ZONE: i32 = 268;
const DST: i32 = 269;
const WORDS: &[(usize, &str, i32, i64)] = &[
    (0, "am", AMPM, 0),
    (0, "pm", AMPM, 1),
    (3, "january", MONTH, 1),
    (3, "february", MONTH, 2),
    (3, "march", MONTH, 3),
    (3, "april", MONTH, 4),
    (3, "may", MONTH, 5),
    (3, "june", MONTH, 6),
    (3, "july", MONTH, 7),
    (3, "august", MONTH, 8),
    (3, "september", MONTH, 9),
    (3, "october", MONTH, 10),
    (3, "november", MONTH, 11),
    (3, "december", MONTH, 12),
    (2, "sunday", DAY, 0),
    (3, "monday", DAY, 1),
    (2, "tuesday", DAY, 2),
    (3, "wednesday", DAY, 3),
    (2, "thursday", DAY, 4),
    (2, "friday", DAY, 5),
    (2, "saturday", DAY, 6),
    (0, "gmt", ZONE, 0),
    (0, "ut", ZONE, 0),
    (0, "utc", ZONE, 0),
    (0, "wet", ZONE, 0),
    (0, "bst", DAYZONE, 0),
    (0, "wat", ZONE, 3600),
    (0, "at", ZONE, 7200),
    (0, "nft", ZONE, 12600),
    (0, "nst", ZONE, 12600),
    (0, "ndt", DAYZONE, 12600),
    (0, "ast", ZONE, 14400),
    (0, "adt", DAYZONE, 14400),
    (0, "est", ZONE, 18000),
    (0, "edt", DAYZONE, 18000),
    (0, "cst", ZONE, 21600),
    (0, "cdt", DAYZONE, 21600),
    (0, "mst", ZONE, 25200),
    (0, "mdt", DAYZONE, 25200),
    (0, "pst", ZONE, 28800),
    (0, "pdt", DAYZONE, 28800),
    (0, "yst", ZONE, 32400),
    (0, "ydt", DAYZONE, 32400),
    (0, "hst", ZONE, 36000),
    (0, "hdt", DAYZONE, 36000),
    (0, "cat", ZONE, 36000),
    (0, "ahst", ZONE, 36000),
    (0, "nt", ZONE, 39600),
    (0, "idlw", ZONE, 43200),
    (0, "cet", ZONE, -3600),
    (0, "met", ZONE, -3600),
    (0, "mewt", ZONE, -3600),
    (0, "mest", DAYZONE, -3600),
    (0, "swt", ZONE, -3600),
    (0, "sst", DAYZONE, -3600),
    (0, "fwt", ZONE, -3600),
    (0, "fst", DAYZONE, -3600),
    (0, "eet", ZONE, -7200),
    (0, "bt", ZONE, -10800),
    (0, "it", ZONE, -12600),
    (0, "zp4", ZONE, -14400),
    (0, "zp5", ZONE, -18000),
    (0, "ist", ZONE, -19800),
    (0, "zp6", ZONE, -21600),
    (0, "wast", ZONE, -25200),
    (0, "wadt", DAYZONE, -25200),
    (0, "jt", ZONE, -27000),
    (0, "cct", ZONE, -28800),
    (0, "jst", ZONE, -32400),
    (0, "cast", ZONE, -34200),
    (0, "cadt", DAYZONE, -34200),
    (0, "east", ZONE, -36000),
    (0, "eadt", DAYZONE, -36000),
    (0, "gst", ZONE, -36000),
    (0, "nzt", ZONE, -43200),
    (0, "nzst", ZONE, -43200),
    (0, "nzdt", DAYZONE, -43200),
    (0, "idle", ZONE, -43200),
    (0, "dst", DST, 0),
    (4, "years", MONTH_UNIT, 12),
    (5, "months", MONTH_UNIT, 1),
    (9, "fortnights", SEC_UNIT, 1209600),
    (4, "weeks", SEC_UNIT, 604800),
    (3, "days", SEC_UNIT, 86400),
    (4, "hours", SEC_UNIT, 3600),
    (3, "minutes", SEC_UNIT, 60),
    (3, "seconds", SEC_UNIT, 1),
    (0, "tomorrow", SEC_UNIT, 86400),
    (0, "yesterday", SEC_UNIT, -86400),
    (0, "today", SEC_UNIT, 0),
    (0, "now", SEC_UNIT, 0),
    (0, "last", NUMBER, -1),
    (0, "this", SEC_UNIT, 0),
    (0, "next", NUMBER, 2),
    (0, "first", NUMBER, 1),
    (0, "1st", NUMBER, 1),
    (0, "2nd", NUMBER, 2),
    (0, "third", NUMBER, 3),
    (0, "3rd", NUMBER, 3),
    (0, "fourth", NUMBER, 4),
    (0, "4th", NUMBER, 4),
    (0, "fifth", NUMBER, 5),
    (0, "5th", NUMBER, 5),
    (0, "sixth", NUMBER, 6),
    (0, "seventh", NUMBER, 7),
    (0, "eighth", NUMBER, 8),
    (0, "ninth", NUMBER, 9),
    (0, "tenth", NUMBER, 10),
    (0, "eleventh", NUMBER, 11),
    (0, "twelfth", NUMBER, 12),
    (0, "ago", AGO, 1),
    (0, "a", ZONE, 3600),
    (0, "b", ZONE, 7200),
    (0, "c", ZONE, 10800),
    (0, "d", ZONE, 14400),
    (0, "e", ZONE, 18000),
    (0, "f", ZONE, 21600),
    (0, "g", ZONE, 25200),
    (0, "h", ZONE, 28800),
    (0, "i", ZONE, 32400),
    (0, "k", ZONE, 36000),
    (0, "l", ZONE, 39600),
    (0, "m", ZONE, 43200),
    (0, "n", ZONE, -3600),
    (0, "o", ZONE, -7200),
    (0, "p", ZONE, -10800),
    (0, "q", ZONE, -14400),
    (0, "r", ZONE, -18000),
    (0, "s", ZONE, -21600),
    (0, "t", ZONE, -25200),
    (0, "u", ZONE, -28800),
    (0, "v", ZONE, -32400),
    (0, "w", ZONE, -36000),
    (0, "x", ZONE, -39600),
    (0, "y", ZONE, -43200),
    (0, "z", ZONE, 0),
];
#[derive(Clone, Copy)]
struct Token(i32, i64);
fn tokens(mut s: &[u8]) -> Option<Vec<Token>> {
    let mut out = Vec::new();
    while let Some(&c) = s.first() {
        if c.is_ascii_whitespace() {
            s = &s[1..];
            continue;
        }
        if c == b'(' {
            let mut depth = 0;
            let mut n = 0;
            for &c in s {
                n += 1;
                if c == b'(' {
                    depth += 1;
                } else if c == b')' {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
            }
            s = &s[n..];
            continue;
        }
        let n = s
            .iter()
            .take_while(|&&c| c.is_ascii_alphanumeric() || c == b'.')
            .count()
            .min(63);
        let word: Vec<u8> = s[..n]
            .iter()
            .filter(|&&c| c != b'.')
            .map(u8::to_ascii_lowercase)
            .collect();
        if let Some(&(_, _, kind, value)) = WORDS.iter().find(|&&(abbr, name, _, _)| {
            word.len() >= if abbr == 0 { name.len() } else { abbr }
                && name.as_bytes().starts_with(&word)
        }) {
            out.push(Token(kind, value));
            s = &s[n..];
        } else if c.is_ascii_digit() {
            let n = s.iter().take_while(|c| c.is_ascii_digit()).count();
            let value = std::str::from_utf8(&s[..n]).ok()?.parse::<i64>().ok()?;
            if value > 9999 {
                return None;
            }
            out.push(Token(NUMBER, value));
            s = &s[n..];
        } else {
            out.push(Token(i32::from(c), 0));
            s = &s[1..];
        }
        if out.len() > 250 {
            return None;
        }
    }
    out.extend([Token(0, 0); 6]);
    Some(out)
}
struct Date {
    year: Option<i64>,
    month: Option<i64>,
    day: Option<i64>,
    time: Option<(i64, i64, i64)>,
    zone: Option<(i64, bool)>,
    weekday: Option<(i64, i64)>,
    rel_sec: i64,
    rel_month: i64,
    rel: bool,
}
fn set<T>(slot: &mut Option<T>, value: T) -> Option<()> {
    if slot.is_some() {
        None
    } else {
        *slot = Some(value);
        Some(())
    }
}
fn convert(
    y: i64,
    m: i64,
    d: i64,
    time: (i64, i64, i64),
    zone: i64,
    dst: Option<bool>,
) -> Option<i64> {
    let y = if y < 69 {
        y.checked_add(2000)?
    } else if y < 100 {
        y.checked_add(1900)?
    } else {
        y
    };
    if !(1970..=9999).contains(&y)
        || !(1..=12).contains(&m)
        || !(0..24).contains(&time.0)
        || !(0..60).contains(&time.1)
        || !(0..60).contains(&time.2)
    {
        return None;
    }
    let mut months = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
        months[1] = 29;
    }
    if d < 1 || d > months[(m - 1) as usize] {
        return None;
    }
    // Upstream counts every fourth year here, including century years.
    let days = (y - 1970) * 365 + (y - 1) / 4 - 1969 / 4
        + months[..(m - 1) as usize].iter().sum::<i64>()
        + d
        - 1;
    let seconds = days * 86400 + zone + time.0 * 3600 + time.1 * 60 + time.2;
    let daylight =
        dst.unwrap_or_else(|| sys::date_clock(seconds, false).is_some_and(|(_, _, dst)| dst));
    Some(seconds - if daylight { 3600 } else { 0 })
}
pub(crate) fn parse(now: i64, input: &[u8]) -> Option<i64> {
    if let Some(s) = input.strip_prefix(b"@") {
        return std::str::from_utf8(s).ok()?.parse::<i64>().ok();
    }
    let tokens = tokens(input)?;
    let mut d = Date {
        year: None,
        month: None,
        day: None,
        time: None,
        zone: None,
        weekday: None,
        rel_sec: 0,
        rel_month: 0,
        rel: false,
    };
    let mut i = 0;
    while tokens[i].0 != 0 {
        let t = &tokens[i..];
        let mut n = 0;
        if t[0].0 == NUMBER && t[1].0 == 58 && t[2].0 == NUMBER {
            let mut time = (t[0].1, t[2].1, 0);
            n = 3;
            if t[3].0 == 58 && t[4].0 == NUMBER {
                time.2 = t[4].1;
                n = 5;
            }
            if t[n].0 == AMPM {
                if time.0 == 12 {
                    time.0 = 0;
                }
                if t[n].1 == 1 {
                    time.0 += 12;
                }
                n += 1;
            }
            set(&mut d.time, time)?;
            if matches!(t[n].0, 43 | 45) && t[n + 1].0 == NUMBER {
                let zone = (t[n + 1].1 / 100 * 3600 + t[n + 1].1 % 100 * 60)
                    * if t[n].0 == 43 { -1 } else { 1 };
                set(&mut d.zone, (zone, false))?;
                n += 2;
            }
        } else if t[0].0 == NUMBER && t[1].0 == AMPM {
            let hour = (if t[0].1 == 12 { 0 } else { t[0].1 }) + if t[1].1 == 1 { 12 } else { 0 };
            set(&mut d.time, (hour, 0, 0))?;
            n = 2;
        } else if matches!(t[0].0, ZONE | DAYZONE) {
            set(&mut d.zone, (t[0].1, t[0].0 == DAYZONE || t[1].0 == DST))?;
            n = if t[1].0 == DST { 2 } else { 1 };
        } else if t[0].0 == NUMBER && matches!(t[1].0, 47 | 45) && t[2].0 == NUMBER {
            let (m, day, year) = if t[1].0 == t[3].0 && t[4].0 == NUMBER {
                n = 5;
                if t[1].0 == 45 || t[0].1 >= 13 {
                    (t[2].1, t[4].1, Some(t[0].1))
                } else {
                    (t[0].1, t[2].1, Some(t[4].1))
                }
            } else if t[1].0 == 47 {
                n = 3;
                (t[0].1, t[2].1, None)
            } else {
                return None;
            };
            set(&mut d.month, m)?;
            set(&mut d.day, day)?;
            if let Some(y) = year {
                set(&mut d.year, y)?;
            }
        } else if t[0].0 == NUMBER
            && t[1].0 == 45
            && t[2].0 == MONTH
            && t[3].0 == 45
            && t[4].0 == NUMBER
        {
            let (y, day) = if t[0].1 > 31 {
                (t[0].1, t[4].1)
            } else {
                (t[4].1, t[0].1)
            };
            set(&mut d.year, y)?;
            set(&mut d.month, t[2].1)?;
            set(&mut d.day, day)?;
            n = 5;
        } else if t[0].0 == MONTH && t[1].0 == NUMBER {
            set(&mut d.month, t[0].1)?;
            set(&mut d.day, t[1].1)?;
            n = 2;
            if t[2].0 == 44 && t[3].0 == NUMBER {
                set(&mut d.year, t[3].1)?;
                n = 4;
            }
        } else if t[0].0 == NUMBER && t[1].0 == MONTH {
            set(&mut d.day, t[0].1)?;
            set(&mut d.month, t[1].1)?;
            n = 2;
            if t[2].0 == NUMBER {
                set(&mut d.year, t[2].1)?;
                n = 3;
            }
        } else if t[0].0 == DAY || (t[0].0 == NUMBER && t[1].0 == DAY) {
            let (ordinal, day) = if t[0].0 == DAY {
                n = 1;
                (1, t[0].1)
            } else {
                n = 2;
                (t[0].1, t[1].1)
            };
            set(&mut d.weekday, (ordinal, day))?;
            if t[n].0 == 44 {
                n += 1;
            }
        } else {
            let (count, unit, used) = if matches!(t[0].0, 43 | 45)
                && t[1].0 == NUMBER
                && matches!(t[2].0, SEC_UNIT | MONTH_UNIT)
            {
                (t[1].1 * if t[0].0 == 45 { -1 } else { 1 }, t[2], 3)
            } else if t[0].0 == NUMBER && matches!(t[1].0, SEC_UNIT | MONTH_UNIT) {
                (t[0].1, t[1], 2)
            } else if matches!(t[0].0, SEC_UNIT | MONTH_UNIT) {
                (1, t[0], 1)
            } else {
                (0, Token(0, 0), 0)
            };
            if used > 0 {
                let value = count.checked_mul(unit.1)?;
                if unit.0 == SEC_UNIT {
                    d.rel_sec = d.rel_sec.checked_add(value)?;
                } else {
                    d.rel_month = d.rel_month.checked_add(value)?;
                }
                d.rel = true;
                n = used;
                if t[n].0 == AGO {
                    d.rel_sec = d.rel_sec.checked_neg()?;
                    d.rel_month = d.rel_month.checked_neg()?;
                    n += 1;
                }
            } else if t[0].0 == NUMBER {
                let value = t[0].1;
                if d.time.is_some() && d.year.is_none() && !d.rel {
                    set(&mut d.year, value)?;
                } else if value < 24 {
                    set(&mut d.time, (value, 0, 0))?;
                } else if value / 100 < 24 && value % 100 < 60 {
                    d.time = Some((value / 100, value % 100, 0));
                } else {
                    return None;
                }
                n = 1;
            }
        }
        if n == 0 {
            return None;
        }
        i += n;
    }
    let (local, default_zone, _) = sys::date_clock(now, false)?;
    let zone = d.zone.map_or(default_zone, |z| z.0);
    let defaults = if d.zone.is_some() {
        sys::date_clock(now.checked_sub(zone)?, true)?.0
    } else {
        local
    };
    let absolute = d.year.is_some()
        || d.month.is_some()
        || d.day.is_some()
        || d.time.is_some()
        || d.weekday.is_some();
    let mut start = if absolute {
        convert(
            d.year.unwrap_or(i64::from(defaults.year) + 1900),
            d.month.unwrap_or(i64::from(defaults.mon) + 1),
            d.day.unwrap_or(i64::from(defaults.mday)),
            d.time.unwrap_or((0, 0, 0)),
            zone,
            d.zone.map(|z| z.1),
        )?
    } else if d.rel {
        now
    } else {
        now.checked_sub(
            i64::from(local.hour) * 3600 + i64::from(local.min) * 60 + i64::from(local.sec),
        )?
    };
    start = start.checked_add(d.rel_sec)?;
    if d.rel_month != 0 {
        let tm = sys::date_clock(start, false)?.0;
        let months = (i64::from(tm.year) + 1900)
            .checked_mul(12)?
            .checked_add(i64::from(tm.mon))?
            .checked_add(d.rel_month)?;
        let future = convert(
            months / 12,
            months % 12 + 1,
            i64::from(tm.mday),
            (i64::from(tm.hour), i64::from(tm.min), i64::from(tm.sec)),
            zone,
            None,
        )?;
        let hour1 = sys::date_clock(start, false)?.0.hour;
        let hour2 = sys::date_clock(future, false)?.0.hour;
        start = future.checked_add(i64::from((hour1 + 1) % 24 - (hour2 + 1) % 24) * 3600)?;
    }
    if let Some((ordinal, day)) = d.weekday
        && d.year.is_none()
        && d.month.is_none()
        && d.day.is_none()
    {
        let weekday = (start.checked_sub(zone)?.div_euclid(86400) + 4).rem_euclid(7);
        let days = (day - weekday + 7) % 7 + 7 * (if ordinal <= 0 { ordinal } else { ordinal - 1 });
        let future = start.checked_add(days.checked_mul(86400)?)?;
        start = if d.zone.is_none() {
            let h1 = sys::date_clock(start, false)?.0.hour;
            let h2 = sys::date_clock(future, false)?.0.hour;
            future.checked_add(i64::from((h1 + 1) % 24 - (h2 + 1) % 24) * 3600)?
        } else {
            future
        };
    }
    Some(if start == -1 { 0 } else { start })
}
