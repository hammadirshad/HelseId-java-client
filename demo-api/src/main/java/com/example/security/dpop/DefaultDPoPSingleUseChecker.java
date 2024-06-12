package com.example.security.dpop;

import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPIssuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.util.singleuse.AlreadyUsedException;
import com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker;
import java.util.AbstractMap.SimpleEntry;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.scheduling.annotation.Scheduled;

public class DefaultDPoPSingleUseChecker implements SingleUseChecker<Map.Entry<DPoPIssuer, JWTID>> {

  private final Set<Map.Entry<DPoPIssuer, JWTID>> jtiSet = ConcurrentHashMap.newKeySet();
  private final Map<JWTID, Long> jtiTimestamps = new ConcurrentHashMap<>();
  private final long jtiMaxAgeSeconds;

  public DefaultDPoPSingleUseChecker(long jtiMaxAgeSeconds) {
    this.jtiMaxAgeSeconds = jtiMaxAgeSeconds;
  }

  @Override
  public void markAsUsed(Map.Entry<DPoPIssuer, JWTID> key) throws AlreadyUsedException {
    JWTID jti = key.getValue();
    long currentTimeSeconds = System.currentTimeMillis() / 1000;

    Long previousTimestamp = jtiTimestamps.putIfAbsent(jti, currentTimeSeconds);
    if (previousTimestamp != null) {
      throw new AlreadyUsedException("The JWTID " + jti.getValue() + " has already been used.");
    }
    jtiSet.add(new SimpleEntry<>(key.getKey(), jti));
  }

  @Scheduled(fixedRateString = "${dpop.purgeInterval:60000}")
  private void purgeExpiredJtis() {
    long currentTimeSeconds = System.currentTimeMillis() / 1000;

    jtiSet.removeIf(
        entry -> {
          JWTID jti = entry.getValue();
          Long timestamp = jtiTimestamps.get(jti);
          if (timestamp == null) {
            return false;
          }
          if ((timestamp + jtiMaxAgeSeconds) < currentTimeSeconds) {
            jtiTimestamps.remove(jti);
            return true;
          }
          return false;
        });
  }
}
