package com.example.controller;

import com.example.model.HelseOidcUser;
import org.json.JSONObject;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class IndexController {

    @RequestMapping("/")
    public String searchForm(Model model, @AuthenticationPrincipal HelseOidcUser user) {
        if (user != null) {
            model.addAttribute("user", user.getFullName());
            model.addAttribute("pid", user.getPid());
            model.addAttribute("security_level", user.getSecurityLevel());
            model.addAttribute("claims", new JSONObject(user.getClaims()).toString(4));
        }
        return "index";
    }


}
