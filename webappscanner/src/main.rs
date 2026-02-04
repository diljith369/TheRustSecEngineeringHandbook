use reqwest::Client;
use scraper::{Html, Selector};
use std::{collections::HashMap, net::Incoming, time::Instant};
struct WebScanner {
    client: Client,
    base_url: String
}

impl WebScanner {
    fn new(base_url: &str)-> Self {
        let client = Client::builder().
        cookie_store(true)
        .build().expect("http client init failed");
    Self {client, base_url: base_url.to_string()}
    }

    async fn login(&self, username: &str, password: &str) ->Result<(), Box<dyn std::error::Error>>
    {
        println!("Login into DVWA");
        let login_url = format!("{}/login.php", self.base_url.trim_end_matches('/'));
        let login_page_resp = self.client.get(&login_url).send().await?.text().await?;
        let token = self.get_user_token(&login_page_resp).await?;
        let login_params = [("username", username), ("password", password), ("Login", "Login"), ("user_token", &token)];
        let login_resp = self.client.post(&login_url).form(&login_params).send().await?;
        //println!("{}", login_resp.text().await?);
        Ok(())

    }

    async fn set_sec_level(&self, sec_level: &str) ->Result<(), Box<dyn std::error::Error>>
    {
        let sec_url = format!("{}/security.php", self.base_url.trim_end_matches('/'));
        let sec_level_resp = self.client.get(&sec_url).send().await?.text().await?;
        let token = self.get_user_token(&sec_level_resp).await?;
        let sec_level_params = [("security", sec_level), ("seclev_submit", "Submit"),  ("user_token", &token)];
        let sec_resp = self.client.post(&sec_url).form(&sec_level_params).send().await?;
        //println!("{}", login_resp.text().await?);
        Ok(())

    }

    async fn verify_xss_r(&self, target_url: &str, xss_payload: &str) ->Result<String, Box<dyn std::error::Error>>
    {
        let mut qry_string = HashMap::new();
        qry_string.insert("name", xss_payload);
        let xss_r_test_resp = self.client.get(target_url).query(&qry_string).send().await?;
        let xss_r_test_resp_text = xss_r_test_resp.text().await?;
        if xss_r_test_resp_text.contains(xss_payload) {
            Ok(format!("XSS Reflected found with payload {} in url {}", xss_payload, target_url))
        } else {
            Ok(format!("XSS Reflected not found with payload {} in url {}", xss_payload, target_url))
        }
    }

    async fn verify_sqli(&self, target_url: &str, sqli_payload: &str) ->Result<String, Box<dyn std::error::Error>>
    {
        let mut baseLine_qry_string = HashMap::new();
        baseLine_qry_string.insert("id", "1");
        baseLine_qry_string.insert("Submit", "Submit");

        let baseLine_qry_resp = self.client.get(target_url).query(&baseLine_qry_string).send().await?;
        let baseLine_qry_resp_text = baseLine_qry_resp.text().await?;

        let mut mal_qry_string = HashMap::new();
        mal_qry_string.insert("id", sqli_payload);
        mal_qry_string.insert("Submit", "Submit");

        let sqlitest_resp = self.client.get(target_url).query(&mal_qry_string).send().await?;
        
        let sqlitest_resp_text = sqlitest_resp.text().await?;
        if sqlitest_resp_text != baseLine_qry_resp_text || sqlitest_resp_text.contains("mysqli_sql_exception") {
            Ok(format!("Potention SQLI found with payload {} in url {}", sqli_payload, target_url))
        } else {
            Ok(format!("SQL Injection not found with payload {} in url {}", sqli_payload, target_url))
        }
    }

    async fn verify_cmdi(&self, target_url: &str, cmdi_payload: &str) ->Result<String, Box<dyn std::error::Error>>
    {
        
        let mut cmdi_params = HashMap::new();
        cmdi_params.insert("ip", cmdi_payload);
        cmdi_params.insert("Submit", "Submit");

        let start = Instant::now();
       
        let cmdi_test_resp = self.client.post(target_url).form(&cmdi_params).send().await?;
        let elapsed_time = start.elapsed();
        if elapsed_time.as_secs() >=3 {
            Ok(format!("Potential Command Injection found with payload {} in url {}", cmdi_payload, target_url))
        } else {
            Ok(format!("No Command Injection found with payload {} in url {}", cmdi_payload, target_url))
        }
    }

 

    async fn verify_xss_s(&self, target_url: &str, xss_payload: &str) ->Result<String, Box<dyn std::error::Error>>
    {
        let mut xss_s_params = HashMap::new();
        xss_s_params.insert("txtName", "test");
        xss_s_params.insert("mtxMessage", xss_payload);
        xss_s_params.insert("btnSign", "Sign+Guestbook");

        //let xss_s_resp = self.client.get(target_url).send().await?;
        //let xss_s_resp_text = xss_s_resp.text().await?;
        //let token = self.get_user_token(&xss_s_resp_text).await?;
        //xss_s_params.insert("user_token", &token);
        let xss_s_test_resp = self.client.post(target_url).form(&xss_s_params).send().await?;
        let xss_s_test_resp_text = xss_s_test_resp.text().await?;
        if xss_s_test_resp_text.contains(xss_payload) {
            Ok(format!("XSS Stored found with payload {} in url {}", xss_payload, target_url))
        } else {
            Ok(format!("XSS Stored not found with payload {} in url {}", xss_payload, target_url))
        }
    }


    


    async fn get_user_token(&self, response: &str) ->Result<String, Box<dyn std::error::Error>> {
        let doc = Html::parse_document(response);
        let token_selector = Selector::parse(r#"input[name="user_token"]"#)?;
        let input = doc.select(&token_selector).next().unwrap();
        let token = input.value().attr("value").unwrap();
        Ok(token.to_string())
    }


}
#[tokio::main]
async fn main()  -> Result<(), Box<dyn std::error::Error>> {
    let scanner = WebScanner::new("http://localhost/DVWA/");
    scanner.login("admin", "password").await?;
    scanner.set_sec_level("low").await?;
    /*let xss_payload = "<script>alert('1');</script>";    
    let xss_r_test_url = "http://localhost/DVWA/vulnerabilities/xss_r/";
    let xss_s_test_url = "http://localhost/DVWA/vulnerabilities/xss_s/";*/

    let sqli_url = "http://localhost/DVWA/vulnerabilities/sqli/";
    let sqli_payload = "1";//"' OR 1=1 #";
    //let sqlires = scanner.verify_sqli(sqli_url, sqli_payload).await?;
    //println!("{}", sqlires);

    let cmdi_url = "http://localhost/DVWA/vulnerabilities/exec/";
    let cmdi_payload = "127.0.0.1; sleep 3";
   // let cmdires = scanner.verify_cmdi(cmdi_url, cmdi_payload).await?;
   // println!("{}", cmdires);
    /*
    let xss_r_res = scanner.verify_xss_r(xss_r_test_url, xss_payload).await?;
    println!("{}", xss_r_res);
    let xss_s_res = scanner.verify_xss_s(xss_s_test_url, xss_payload).await?;
    println!("{}", xss_s_res);*/

    let (sqli_res, cmdi_res) = tokio::join!(scanner.verify_sqli(sqli_url, sqli_payload), 
                                              scanner.verify_cmdi(cmdi_url, cmdi_payload));
    println!("{}", sqli_res?);
    println!("{}", cmdi_res?);

    Ok(())
}
