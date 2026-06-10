package com.example1.demo;

import com.example1.demo.util.Constants;
import com.google.gson.Gson;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;



@SpringBootApplication
public class DemoApplication {

	public static void main(String[] args) throws Exception {

		Transcript transcript = new Transcript();
		transcript.setGrantType(Constants.GRANT_TYPE);
		transcript.setAssertion("this is assertion");
		Gson gson = new Gson();

		String jsonRequest = gson.toJson(transcript);
		String myAPISecret = Constants.CONSUMER_SECRET;

		System.out.println(jsonRequest);
		System.out.println(myAPISecret);

		SpringApplication.run(DemoApplication.class, args);
	}

}



//Note
//Reference: https://www.youtube.com/watch?v=9oq7Y8n1t00 --> how to call a REST API in Java
