package com.example1.demo;

public class Transcript {

    private String grant_type;
    private String assertion;
    
    public String getGrantType() {
        return grant_type;
    }

    public void setGrantType(String grant_type) {
        this.grant_type = grant_type;
    }
    

    public String getAssertion() {
        return assertion;
    }

    public void setAssertion(String assertion) {
        this.assertion = assertion;
    }

}


//note: this to create a JSON format