use x509_parser::{
    pem::Pem,
    certificate::X509Certificate,
};
use time::format_description;
use anyhow::{Result, Context};
use ansi_term::Colour;

struct X509CertificateSummary {
    subject: String,
    issuer: String,
    not_before: String,
    not_after: String,
    serial_number: String,
    self_signed: String,
}

impl X509CertificateSummary {
    fn new(x509: &X509Certificate) -> Result<X509CertificateSummary> {
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

        let mut issuer = String::new();
        let mut first = true;
        for cn in x509.issuer().iter_common_name() {
            let cn = cn.as_str().context("the x509 common name cannot be interpreted as a string")?; 
            if !first {
                issuer.push_str(", ");
            }
            issuer.push_str(cn);
            first = false;
        }

        let format = format_description::parse("[year]-[month]-[day]").context("the date format is invalid")?;
        let nb = x509.validity().not_before.to_datetime().format(&format).context("the validity date cannot be formatted")?;
        let na = x509.validity().not_after.to_datetime().format(&format).context("the validity date cannot be formatted")?;

        Ok(X509CertificateSummary{
            subject,
            issuer,
            not_after: na,
            not_before: nb,
            serial_number: x509.raw_serial_as_string(),
            self_signed: (x509.issuer == x509.subject).to_string()
        })
    }
}

fn formatted_key(key: &str, porcelain: bool) -> String {
    if porcelain {
        key.to_string()
    } else {
        Colour::RGB(249, 38, 114).paint(key).to_string()
    }
}

fn formatted_value(value: &str, porcelain: bool) -> String {
    if porcelain {
        value.to_string()
    } else {
        Colour::RGB(0xE6, 0xDB, 0x74).paint(value).to_string()
    }
}

pub fn formatted_row(key: &str, value: &str, porcelain: bool) -> String {
    format!("{}: {}", formatted_key(key, porcelain), formatted_value(value, porcelain))
}

pub fn summarize(data: &[u8], porcelain: bool) -> Result<()> {
    for pem in Pem::iter_from_buffer(data) {
        let pem = pem.context("given data cannot be interpreted as PEM")?;
        let x509 = pem.parse_x509().context("PEM does not contain a valid x509 certificate")?;
        let summary = X509CertificateSummary::new(&x509).context("X509 cannot be summarized")?;
        let (w, _) = term_size::dimensions().unwrap();
        print!("{}
    {}
    {}
    {}
    {}
    {}
    {}
",
            std::iter::repeat("─").take(w).collect::<String>(),
            formatted_row("subject", &summary.subject, porcelain),
            formatted_row("issuer", &summary.issuer, porcelain),
            formatted_row("not before", &summary.not_before, porcelain),
            formatted_row("not after", &summary.not_after, porcelain),
            formatted_row("serial number", &summary.serial_number, porcelain),
            formatted_row("self signed", &summary.self_signed, porcelain),
        )
    }
    Ok(())
}
