package com.mycompany.webapp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import lombok.extern.log4j.Log4j2;

@Controller
@Log4j2
public class HomeController {
	@RequestMapping("/")
	public String home() {
		log.error("실행");
		log.warn("실행");
		log.info("실행");
		log.debug("실행");
		return "home";
	}
}
