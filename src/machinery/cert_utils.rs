use x509_parser::{
    pem::Pem,
    certificate::X509Certificate,
};
use time::format_description;

fn summary(x509: &X509Certificate) -> String {
    let mut subject = String::new();
    let mut first = true;
    for cn in x509.subject().iter_common_name() {
        match cn.as_str() {
            Ok(cn) => {
                if !first {
                    subject.push_str(", ");    
                }
                subject.push_str(cn);
                first = false;
            },
            Err(_) => {

            }
        };
    }

    let format = format_description::parse("[year]-[month]-[day]").unwrap();
    let nb = x509.validity().not_before.to_datetime().format(&format).unwrap();
    let na = x509.validity().not_after.to_datetime().format(&format).unwrap();
    
    let is_ca: &str;
    if x509.issuer == x509.subject {
        is_ca = " (Self Signed)";
    } else {
        is_ca = "";
    }

    format!("Subject: {}. Not before: {}. Not after: {}. Serial: {}{}", subject, nb, na, x509.raw_serial_as_string(), is_ca)
}

pub fn dump(data: &[u8]) {
    for pem in Pem::iter_from_buffer(data) {
        match pem {
            Ok(pem) => {
                match pem.parse_x509() {
                    Ok(x509) => {
                        println!("{}", summary(&x509));
                    },
                    Err(e) => {
                        println!("error: {}", e)
                    }
                };
            },
            Err(e) => {
                println!("error: {}", e);
            }
        }
    }
}
