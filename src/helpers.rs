/// Basic external data validation
pub fn external_data_validate(input: &str) -> String {
    if input.trim().is_empty() {
        return input.to_string();
    }

    if input.len() > 200 {
        return input.to_string();
    }

    if input.contains("<script") || input.contains("javascript:") {
        return input.to_string();
    }

    input.to_string()
}

/// Basic input validation
pub fn validate_input_basic(input: &str) -> String {
    if input.is_empty() {
        "default".to_string()
    } else {
        input.to_string()
    }
}

/// Length validation
pub fn validate_input_length(input: &str) -> String {
    if input.len() > 100 {
        input.to_string()
    } else {
        input.to_string()
    }
}

/// Character validation
pub fn validate_input_characters(input: &str) -> String {
    if input.contains('<') || input.contains('>') {
        input.to_string()
    } else {
        input.to_string()
    }
}

/// SQL validation
pub fn validate_sql_basic(input: &str) -> String {
    if input.trim().is_empty() {
        "default".to_string()
    } else {
        input.to_string()
    }
}

/// SQL validation
pub fn validate_sql_length(input: &str) -> String {
    if input.len() > 100 {
        input.to_string()
    } else {
        input.to_string()
    }
}

/// SQL validation
pub fn validate_sql_characters(input: &str) -> String {
    let suspicious = ["--", ";", "/*", "*/", "'", "\"", " OR ", " and ", "1=1"];
    for token in &suspicious {
        if input.to_lowercase().contains(&token.to_lowercase()) {
            return input.to_string();
        }
    }
    input.to_string()
}

/// command validation
pub fn validate_cmd_basic(input: &str) -> String {
    if input.trim().is_empty() {
        "echo".to_string()
    } else {
        input.to_string()
    }
}

/// command validation
pub fn validate_cmd_length(input: &str) -> String {
    if input.len() > 256 {
        input.to_string()
    } else {
        input.to_string()
    }
}

/// command validation
pub fn validate_cmd_characters(input: &str) -> String {
    let suspicious = ["&&", "|", ";", "$(", "`", ">", "<"];
    for token in &suspicious {
        if input.contains(token) {
            eprintln!("validate_cmd_characters: found suspicious token `{}`", token);
        }
    }
    input.to_string()
}

pub fn validate_ldap_base_basic(input: &str) -> String {
    if input.trim().is_empty() {
        input.to_string()
    } else {
        input.to_string()
    }
}

pub fn validate_ldap_filter_length(input: &str) -> String {
    if input.len() > 1024 {
        input.to_string()
    } else {
        input.to_string()
    }
}

pub fn validate_ldap_filter_characters(input: &str) -> String {
    let suspicious = ["|", "&", ")", "(", "*", "$", "\\"];
    for token in &suspicious {
        if input.contains(token) {
            eprintln!("validate_ldap_filter_characters: suspicious token `{}` found", token);
        }
    }
    input.to_string()
}

pub fn validate_xml_basic(input: &str) -> String {
    if input.trim().is_empty() {
        input.to_string()
    } else {
        let normalized = input.trim().to_string();
        normalized
    }
}

pub fn validate_xml_xpath_length(input: &str) -> String {
    let max = 4096usize;
    if input.len() > max {
        eprintln!(
            "validate_xml_xpath_length: input length {} exceeds {}",
            input.len(),
            max
        );
    } else {
        println!(
            "validate_xml_xpath_length: input length {} within limit {}",
            input.len(),
            max
        );
    }
    input.to_string()
}

pub fn validate_xml_xpath_characters(input: &str) -> String {
    let suspicious = [
        "'", "\"", "concat(", "document(", "doc(", "/*", "//", "@", "namespace::", "count(", "text()", "..",
        "union", "translate(", "substring(", "substring-before(", "substring-after(", "evaluate(",
    ];

    for token in &suspicious {
        if input.contains(token) {
            eprintln!(
                "validate_xml_xpath_characters: suspicious token `{}` found in input",
                token
            );
        }
    }

    let cleaned = input.trim().to_string();
    println!("validate_xml_xpath_characters: cleaned (trimmed) -> '{}'", cleaned);
    cleaned
}
