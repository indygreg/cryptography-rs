// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! ASN.1 primitives related to time types.

use {
    bcder::{
        decode::{Constructed, DecodeError, Primitive, SliceSource, Source},
        encode::{PrimitiveContent, Values},
        Mode, Tag,
    },
    chrono::{Datelike, TimeZone, Timelike},
    std::{
        fmt::{Display, Formatter},
        io::Write,
        ops::{Add, Deref},
        str::FromStr,
    },
};

/// Timezone formats of [GeneralizedTime] to allow.
///
/// X.690 allows [GeneralizedTime] to have multiple timezone formats. However,
/// various RFCs restrict which formats are allowed. This enumeration exists to
/// express which formats should be allowed by a parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneralizedTimeAllowedTimezone {
    /// Allow either `Z` or timezone offset formats.
    Any,

    /// `Z` timezone identifier only.
    Z,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Time {
    UtcTime(UtcTime),
    GeneralTime(GeneralizedTime),
}

impl Time {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_primitive(|tag, prim| match tag {
            Tag::UTC_TIME => Ok(Self::UtcTime(UtcTime::from_primitive(prim)?)),
            Tag::GENERALIZED_TIME => Ok(Self::GeneralTime(
                GeneralizedTime::from_primitive_no_fractional_or_timezone_offsets(prim)?,
            )),
            _ => Err(prim.content_err(format!("expected UTCTime or GeneralizedTime; got {}", tag))),
        })
    }

    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_primitive(|tag, prim| match tag {
            Tag::UTC_TIME => Ok(Self::UtcTime(UtcTime::from_primitive(prim)?)),
            Tag::GENERALIZED_TIME => Ok(Self::GeneralTime(
                GeneralizedTime::from_primitive_no_fractional_or_timezone_offsets(prim)?,
            )),
            _ => Err(prim.content_err(format!("expected UTCTime or GeneralizedTime; got {}", tag))),
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        match self {
            Self::UtcTime(utc) => (Some(utc.encode()), None),
            Self::GeneralTime(gt) => (None, Some(gt.encode())),
        }
    }
}

impl From<chrono::DateTime<chrono::Utc>> for Time {
    fn from(t: chrono::DateTime<chrono::Utc>) -> Self {
        Self::UtcTime(UtcTime(t))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Zone {
    Utc,
    Offset(chrono::FixedOffset),
}

impl Display for Zone {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Utc => f.write_str("Z"),
            Self::Offset(offset) => f.write_str(format!("{}", offset).replace(':', "").as_str()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneralizedTime {
    time: chrono::NaiveDateTime,
    fractional_seconds: bool,
    timezone: Zone,
}

impl GeneralizedTime {
    /// Take a value, not allowing fractional seconds and requiring the `Z` timezone identifier.
    pub fn take_from_no_fractional_z<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_primitive_if(Tag::GENERALIZED_TIME, |prim| {
            Self::from_primitive_no_fractional_or_timezone_offsets(prim)
        })
    }

    /// Take a value, allowing fractional seconds and requiring the `Z` timezone identifier.
    pub fn take_from_allow_fractional_z<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_primitive_if(Tag::GENERALIZED_TIME, |prim| {
            let data = prim.take_all()?;

            Self::parse(
                SliceSource::new(data.as_ref()),
                true,
                GeneralizedTimeAllowedTimezone::Z,
            )
            .map_err(|e| e.convert())
        })
    }

    /// Parse a [GeneralizedTime] from a primitive string and don't allow fractional seconds or timezone offsets.
    pub fn from_primitive_no_fractional_or_timezone_offsets<S: Source>(
        prim: &mut Primitive<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let data = prim.take_all()?;

        Self::parse(
            SliceSource::new(data.as_ref()),
            false,
            GeneralizedTimeAllowedTimezone::Z,
        )
        .map_err(|e| e.convert())
    }

    /// Parse GeneralizedTime string data.
    pub fn parse(
        source: SliceSource,
        allow_fractional_seconds: bool,
        tz: GeneralizedTimeAllowedTimezone,
    ) -> Result<Self, DecodeError<<SliceSource as Source>::Error>> {
        let data = source.slice();

        // This form is common and is most strict. So check for it quickly.
        if !allow_fractional_seconds
            && matches!(tz, GeneralizedTimeAllowedTimezone::Z)
            && data.len() != "YYYYMMDDHHMMSSZ".len()
        {
            return Err(source.content_err(format!(
                "{} is not of format YYYYMMDDHHMMSSZ",
                String::from_utf8_lossy(data)
            )));
        }

        if data.len() < 15 {
            return Err(source.content_err("GeneralizedTime value too short"));
        }

        let year = i32::from_str(
            std::str::from_utf8(&data[0..4]).map_err(|s| source.content_err(s.to_string()))?,
        )
        .map_err(|s| source.content_err(s.to_string()))?;
        let month = u32::from_str(
            std::str::from_utf8(&data[4..6]).map_err(|s| source.content_err(s.to_string()))?,
        )
        .map_err(|s| source.content_err(s.to_string()))?;
        let day = u32::from_str(
            std::str::from_utf8(&data[6..8]).map_err(|s| source.content_err(s.to_string()))?,
        )
        .map_err(|s| source.content_err(s.to_string()))?;
        let hour = u32::from_str(
            std::str::from_utf8(&data[8..10]).map_err(|s| source.content_err(s.to_string()))?,
        )
        .map_err(|s| source.content_err(s.to_string()))?;
        let minute = u32::from_str(
            std::str::from_utf8(&data[10..12]).map_err(|s| source.content_err(s.to_string()))?,
        )
        .map_err(|s| source.content_err(s.to_string()))?;
        let second = u32::from_str(
            std::str::from_utf8(&data[12..14]).map_err(|s| source.content_err(s.to_string()))?,
        )
        .map_err(|s| source.content_err(s.to_string()))?;

        let remaining = &data[14..];

        let (nano, remaining) = match allow_fractional_seconds {
            true => {
                if remaining.starts_with(b".") {
                    if let Some((nondigit_offset, _)) = remaining
                        .iter()
                        .enumerate()
                        .skip(1)
                        .find(|(_, c)| !c.is_ascii_digit())
                    {
                        let digits_count = nondigit_offset - 1;

                        let (digits, remaining) = remaining.split_at(nondigit_offset);

                        let mut digits = std::str::from_utf8(&digits[1..])
                            .map_err(|s| source.content_err(s.to_string()))?
                            .to_string();
                        digits.extend(std::iter::repeat('0').take(9 - digits_count));

                        (
                            u32::from_str(&digits)
                                .map_err(|s| source.content_err(s.to_string()))?,
                            remaining,
                        )
                    } else {
                        return Err(source.content_err(
                            "failed to locate timezone identifier after fractional seconds",
                        ));
                    }
                } else {
                    (0, remaining)
                }
            }
            false => (0, remaining),
        };

        let timezone = match tz {
            GeneralizedTimeAllowedTimezone::Z => {
                if remaining != b"Z" {
                    return Err(source.content_err(format!(
                        "timezone identifier {} not `Z`",
                        String::from_utf8_lossy(remaining)
                    )));
                }

                Zone::Utc
            }
            GeneralizedTimeAllowedTimezone::Any => {
                if remaining == b"Z" {
                    Zone::Utc
                } else {
                    if remaining.len() != 5 {
                        return Err(source.content_err(format!(
                            "`{}` is not a 5 character timezone identifier",
                            String::from_utf8_lossy(remaining)
                        )));
                    }

                    let east = match remaining[0] {
                        b'+' => true,
                        b'-' => false,
                        _ => {
                            return Err(source.content_err(format!(
                                "`{}` does not begin with a +- offset",
                                String::from_utf8_lossy(remaining)
                            )))
                        }
                    };

                    let offset_hours = u32::from_str(
                        std::str::from_utf8(&remaining[1..3])
                            .map_err(|s| source.content_err(s.to_string()))?,
                    )
                    .map_err(|s| source.content_err(s.to_string()))?;
                    let offset_minutes = u32::from_str(
                        std::str::from_utf8(&remaining[3..])
                            .map_err(|s| source.content_err(s.to_string()))?,
                    )
                    .map_err(|s| source.content_err(s.to_string()))?;

                    let offset_seconds = (offset_hours * 3600 + offset_minutes * 60) as i32;

                    Zone::Offset(if east {
                        chrono::FixedOffset::east_opt(offset_seconds)
                            .ok_or_else(|| source.content_err("bad timezone time"))?
                    } else {
                        chrono::FixedOffset::west_opt(offset_seconds)
                            .ok_or_else(|| source.content_err("bad timezone offset"))?
                    })
                }
            }
        };

        if let chrono::LocalResult::Single(dt) =
            chrono::Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
        {
            if let Some(dt) = dt.with_nanosecond(nano) {
                Ok(Self {
                    time: dt.naive_utc(),
                    fractional_seconds: allow_fractional_seconds,
                    timezone,
                })
            } else {
                Err(source.content_err("invalid time value"))
            }
        } else {
            Err(source.content_err("invalid datetime value"))
        }
    }
}

impl ToString for GeneralizedTime {
    fn to_string(&self) -> String {
        format!(
            "{}{}",
            self.time.format(if self.fractional_seconds {
                "%Y%m%d%H%M%S%.f"
            } else {
                "%Y%m%d%H%M%S"
            }),
            self.timezone
        )
    }
}

impl From<GeneralizedTime> for chrono::DateTime<chrono::Utc> {
    fn from(gt: GeneralizedTime) -> Self {
        match gt.timezone {
            Zone::Utc => chrono::DateTime::<chrono::Utc>::from_utc(gt.time, chrono::Utc),
            Zone::Offset(offset) => {
                chrono::DateTime::<chrono::Utc>::from_utc(gt.time.add(offset), chrono::Utc)
            }
        }
    }
}

impl From<chrono::DateTime<chrono::Utc>> for GeneralizedTime {
    fn from(utc: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            time: utc.naive_utc(),
            fractional_seconds: utc.timestamp_subsec_micros() > 0,
            timezone: Zone::Utc,
        }
    }
}

impl PrimitiveContent for GeneralizedTime {
    const TAG: Tag = Tag::GENERALIZED_TIME;

    fn encoded_len(&self, _: Mode) -> usize {
        self.to_string().len()
    }

    fn write_encoded<W: Write>(&self, _: Mode, target: &mut W) -> Result<(), std::io::Error> {
        target.write_all(self.to_string().as_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UtcTime(chrono::DateTime<chrono::Utc>);

impl UtcTime {
    /// Obtain a new instance with now as the time.
    pub fn now() -> Self {
        Self(chrono::Utc::now())
    }

    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_primitive_if(Tag::UTC_TIME, |prim| Self::from_primitive(prim))
    }

    pub fn from_primitive<S: Source>(
        prim: &mut Primitive<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let data = prim.take_all()?;

        if data.len() != "YYMMDDHHMMSSZ".len() {
            return Err(prim.content_err("UTCTime not of expected length"));
        }

        let year = i32::from_str(
            std::str::from_utf8(&data[0..2]).map_err(|s| prim.content_err(s.to_string()))?,
        )
        .map_err(|s| prim.content_err(s.to_string()))?;

        let year = if year >= 50 { year + 1900 } else { year + 2000 };

        let month = u32::from_str(
            std::str::from_utf8(&data[2..4]).map_err(|s| prim.content_err(s.to_string()))?,
        )
        .map_err(|s| prim.content_err(s.to_string()))?;
        let day = u32::from_str(
            std::str::from_utf8(&data[4..6]).map_err(|s| prim.content_err(s.to_string()))?,
        )
        .map_err(|s| prim.content_err(s.to_string()))?;
        let hour = u32::from_str(
            std::str::from_utf8(&data[6..8]).map_err(|s| prim.content_err(s.to_string()))?,
        )
        .map_err(|s| prim.content_err(s.to_string()))?;
        let minute = u32::from_str(
            std::str::from_utf8(&data[8..10]).map_err(|s| prim.content_err(s.to_string()))?,
        )
        .map_err(|s| prim.content_err(s.to_string()))?;
        let second = u32::from_str(
            std::str::from_utf8(&data[10..12]).map_err(|s| prim.content_err(s.to_string()))?,
        )
        .map_err(|s| prim.content_err(s.to_string()))?;

        if data[12] != b'Z' {
            return Err(prim.content_err("UTCTime must end with `Z`"));
        }

        if let chrono::LocalResult::Single(dt) =
            chrono::Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
        {
            Ok(Self(dt))
        } else {
            Err(prim.content_err("invalid year month day hour minute second value"))
        }
    }
}

impl ToString for UtcTime {
    fn to_string(&self) -> String {
        format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            self.0.year() % 100,
            self.0.month(),
            self.0.day(),
            self.0.hour(),
            self.0.minute(),
            self.0.second()
        )
    }
}

impl Deref for UtcTime {
    type Target = chrono::DateTime<chrono::Utc>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PrimitiveContent for UtcTime {
    const TAG: Tag = Tag::UTC_TIME;

    fn encoded_len(&self, _: Mode) -> usize {
        self.to_string().len()
    }

    fn write_encoded<W: Write>(&self, _: Mode, target: &mut W) -> Result<(), std::io::Error> {
        target.write_all(self.to_string().as_bytes())
    }
}

#[cfg(test)]
mod test {
    use {super::*, bcder::decode::ContentError};

    #[test]
    fn generalized_time() -> Result<(), ContentError> {
        let gt = GeneralizedTime {
            time: chrono::NaiveDateTime::from_timestamp_opt(1643510772, 0).unwrap(),
            fractional_seconds: false,
            timezone: Zone::Utc,
        };
        assert_eq!(gt.to_string(), "20220130024612Z");

        let gt = GeneralizedTime {
            time: chrono::NaiveDateTime::from_timestamp_opt(1643510772, 0).unwrap(),
            fractional_seconds: false,
            timezone: Zone::Offset(chrono::FixedOffset::east_opt(3600).unwrap()),
        };
        assert_eq!(gt.to_string(), "20220130024612+0100");

        let gt = GeneralizedTime {
            time: chrono::NaiveDateTime::from_timestamp_opt(1643510772, 0).unwrap(),
            fractional_seconds: false,
            timezone: Zone::Offset(chrono::FixedOffset::west_opt(7200).unwrap()),
        };
        assert_eq!(gt.to_string(), "20220130024612-0200");

        let gt = GeneralizedTime::parse(
            SliceSource::new(b"20220129133742Z"),
            true,
            GeneralizedTimeAllowedTimezone::Z,
        )?;
        assert_eq!(gt.time.year(), 2022);
        assert_eq!(gt.time.month(), 1);
        assert_eq!(gt.time.day(), 29);
        assert_eq!(gt.time.hour(), 13);
        assert_eq!(gt.time.minute(), 37);
        assert_eq!(gt.time.second(), 42);
        assert_eq!(gt.time.nanosecond(), 0);
        assert_eq!(format!("{}", gt.timezone), "Z");

        assert_eq!(gt.to_string(), "20220129133742Z");

        let gt = GeneralizedTime::parse(
            SliceSource::new(b"20220129133742.333Z"),
            true,
            GeneralizedTimeAllowedTimezone::Z,
        )?;
        assert_eq!(gt.to_string(), "20220129133742.333Z");

        let gt = GeneralizedTime::parse(
            SliceSource::new(b"20220129133742-0800"),
            false,
            GeneralizedTimeAllowedTimezone::Any,
        )?;
        assert_eq!(format!("{}", gt.timezone), "-0800");

        let gt = GeneralizedTime::parse(
            SliceSource::new(b"20220129133742+1000"),
            false,
            GeneralizedTimeAllowedTimezone::Any,
        )?;
        assert_eq!(format!("{}", gt.timezone), "+1000");

        let gt = GeneralizedTime::parse(
            SliceSource::new(b"20220129133742.333-0800"),
            true,
            GeneralizedTimeAllowedTimezone::Any,
        )?;
        assert_eq!(gt.to_string(), "20220129133742.333-0800");

        Ok(())
    }

    #[test]
    fn generalized_time_invalid() {
        for allow_fractional_seconds in [false, true] {
            for allowed_timezone in [
                GeneralizedTimeAllowedTimezone::Any,
                GeneralizedTimeAllowedTimezone::Z,
            ] {
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b""),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"abcd"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"2022"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"202201"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"2022013012"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"202201301230"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015."),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015.a"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015.0a"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015a"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015-"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015+"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015+01"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015+01000"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015+0100a"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015-01000"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
                assert!(GeneralizedTime::parse(
                    SliceSource::new(b"20220130123015-0100a"),
                    allow_fractional_seconds,
                    allowed_timezone
                )
                .is_err());
            }
        }
    }
}
