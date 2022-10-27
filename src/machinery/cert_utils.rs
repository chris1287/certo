use x509_parser::{
    pem::Pem,
    certificate::X509Certificate,
};
use time::format_description;
use anyhow::{Result, Context};

fn generate_summary(x509: &X509Certificate) -> Result<String> {
    let mut subject = String::new();
    let mut first = true;
    for cn in x509.subject().iter_common_name() {
        let cn = cn.as_str().context("the x509 common name cannot be interpreted as a string")?; 
        if !first {
            subject.push_str(", ");    
        }
        subject.push_str(cn);
        first = false;
    }

    let format = format_description::parse("[year]-[month]-[day]").context("the date format is invalid")?;
    let nb = x509.validity().not_before.to_datetime().format(&format).context("the validity date cannot be formatted")?;
    let na = x509.validity().not_after.to_datetime().format(&format).context("the validity date cannot be formatted")?;
    
    let is_ca: &str;
    if x509.issuer == x509.subject {
        is_ca = " (Self Signed)";
    } else {
        is_ca = "";
    }

    Ok(format!("Subject: {}. Not before: {}. Not after: {}. Serial: {}{}", subject, nb, na, x509.raw_serial_as_string(), is_ca))
}

pub fn summarize(data: &[u8]) -> Result<()> {
    for pem in Pem::iter_from_buffer(data) {
        let pem = pem.context("given data cannot be interpreted as PEM")?;
        let x509 = pem.parse_x509().context("PEM does not contain a valid x509 certificate")?; 
        println!("{}", generate_summary(&x509).context("x509 summary cannot be generated")?);
    }
    Ok(())
}
