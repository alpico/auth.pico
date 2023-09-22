//! Authorization header parsing.

/// The auth-header fields.
///
/// Example: `Authorization: alpico key=0, sig=$(dd if=/dev/urandom bs=64 count=1 | base64 -w 0 | tr '/+' '_-' | tr -d '=')`
#[derive(Default, Debug, PartialEq)]
pub struct AuthHeader {
    pub start: u64,
    pub duration: u64,
    pub sig: String,
    pub key: u32,
    pub add: Vec<String>,
    pub header: String,
}

impl AuthHeader {
    pub fn new(header: &str) -> Result<Self, &'static str> {
        let mut res = Self {
            add: vec!["-method".to_string(), "-path".to_string()],
            ..Default::default()
        };

        let stripped_header = header
            .trim_start()
            .strip_prefix("alpico ")
            .ok_or("scheme unsupported")?;
        for item in stripped_header.split(',').map(str::trim) {
            let (key, value) = item.split_once('=').ok_or("separator")?;
            let value = value.trim();
            match key.trim() {
                "add" => {
                    res.add = value.split('+').map(str::to_string).collect();
                }
                "key" => {
                    res.key = str::parse(value).or(Err("key"))?;
                }
                "sig" => {
                    res.sig = value.to_string();
                }
                "time" => {
                    let (start, duration) = value.split_once('+').ok_or("time")?;
                    res.start = str::parse(start).or(Err("start"))?;
                    res.duration = str::parse(duration).or(Err("duration"))?;
                }
                &_ => return Err("unknown param"),
            }
        }

        // drop the signature string
        let (left, right) = header.split_once(res.sig.as_str()).unwrap();
        // the rsplit_once is possible here since the signature can not be the first parameter in the header
        res.header
            .push_str(left.rsplit_once(',').map(|x| x.0).unwrap_or(left));
        res.header.push_str(right);
        Ok(res)
    }
}

#[test]
fn test_scheme() {
    assert_eq!(Err("scheme unsupported"), AuthHeader::new(""));
    assert_eq!(Err("scheme unsupported"), AuthHeader::new("Bearer"));
    assert_eq!(Err("scheme unsupported"), AuthHeader::new("alpico"));
    assert_ne!(Err("scheme unsupported"), AuthHeader::new("alpico "));
    assert_ne!(Err("scheme unsupported"), AuthHeader::new("  alpico "));
}

#[test]
fn test_separator() {
    assert_eq!(Err("separator"), AuthHeader::new("alpico a"));
    assert_eq!(Err("separator"), AuthHeader::new("alpico ,"));
    assert_ne!(Err("separator"), AuthHeader::new("alpico add="));
    assert_eq!(Err("separator"), AuthHeader::new("alpico add=, bar"));
}

#[test]
fn test_params() {
    assert_eq!(Err("unknown param"), AuthHeader::new("alpico ="));
    assert_eq!(Err("unknown param"), AuthHeader::new("alpico dummy=1"));
    assert_eq!("foo", AuthHeader::new("alpico sig=foo").unwrap().sig);
    assert_eq!("foo", AuthHeader::new("alpico add=foo").unwrap().add[0]);
    assert_eq!(
        3,
        AuthHeader::new("alpico add=foo+bar+baz").unwrap().add.len()
    );
    assert_eq!(
        "bar",
        AuthHeader::new("alpico add=foo+bar+baz").unwrap().add[1]
    );
    assert_eq!(Err("time"), AuthHeader::new("alpico time=1"));
    assert_eq!(Err("start"), AuthHeader::new("alpico time=-4+1"));
    assert_eq!(Err("start"), AuthHeader::new("alpico time=b+1"));
    assert_eq!(Err("duration"), AuthHeader::new("alpico time=42+-1"));
    assert_eq!(Err("duration"), AuthHeader::new("alpico time=42+0b1"));
    assert_eq!(42, AuthHeader::new("alpico time=42+1").unwrap().start);
    assert_eq!(0, AuthHeader::new("alpico time=42+0").unwrap().duration);
    assert_eq!(12, AuthHeader::new("alpico time=42+12").unwrap().duration);
    assert_eq!(42, AuthHeader::new("alpico key=42, sig=").unwrap().key);
}

#[test]
fn test_signature_split() {
    assert_eq!(
        "alpico time=41+1",
        AuthHeader::new("alpico time=41+1,sig=foo").unwrap().header
    );
    assert_eq!(
        "alpico time=41+1 ,add=",
        AuthHeader::new("alpico time=41+1,sig=foo ,add=")
            .unwrap()
            .header
    );
    assert_eq!(
        "alpico sig=,add=",
        AuthHeader::new("alpico sig=foo,add=").unwrap().header
    );
}

#[test]
fn test_derived() {
    let mut x = AuthHeader::new("alpico add=-method+-path, sig=, time=0+0, key=0").unwrap();
    x.header = "alpico sig=".to_string();
    assert_eq!(x, AuthHeader::new("alpico sig=").unwrap());
    // use the debug prinn
    println!("{x:?}");
}
