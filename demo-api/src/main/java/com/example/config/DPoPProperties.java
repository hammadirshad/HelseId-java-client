package com.example.config;

import com.nimbusds.jose.JWSAlgorithm;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "dpop")
@Data
public class DPoPProperties {

  private long purgeInterval;
  private long proofMaxAgeSeconds;
  private long jtiMaxAgeSeconds;
  private Set<JWSAlgorithm> supportedAlgs =
      new HashSet<>(
          Arrays.asList(
              JWSAlgorithm.RS256,
              JWSAlgorithm.RS384,
              JWSAlgorithm.RS512,
              JWSAlgorithm.PS256,
              JWSAlgorithm.PS384,
              JWSAlgorithm.PS512,
              JWSAlgorithm.ES256,
              JWSAlgorithm.ES384,
              JWSAlgorithm.ES512));
}
