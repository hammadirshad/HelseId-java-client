package com.example.model;

import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class DPoPToken {

  private String tokenType;
  private String tokenValue;
  private Set<String> scopes;
  private String dPoPHeader;

}
