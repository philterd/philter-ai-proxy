/*
 *     Copyright 2026 Philterd, LLC @ https://www.philterd.ai
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *          http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ai.philterd.aiproxy.proxy;

import ai.philterd.aiproxy.config.ProxyProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * The client address recorded in the audit log. {@code X-Forwarded-For} is believed only from the trusted proxies
 * configured in {@code proxy.security.trusted-proxies} (none by default). The header is read from the right,
 * skipping trusted proxies, since each proxy appends the address it received from and a client can write the
 * leftmost entries itself. Only IP addresses are accepted; nothing is looked up in DNS.
 */
@Component
public class ClientAddress {

    private record Cidr(byte[] network, int prefix) {

        boolean contains(final byte[] address) {
            if (address.length != network.length) {
                return false;
            }
            final int bits = address.length * 8;
            final BigInteger mask = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE)
                    .shiftRight(prefix).not().and(BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE));
            return new BigInteger(1, address).and(mask).equals(new BigInteger(1, network).and(mask));
        }
    }

    private final List<Cidr> trusted = new ArrayList<>();

    public ClientAddress(final ProxyProperties properties) {
        for (final String entry : properties.security().trustedProxies()) {
            final String[] parts = entry.strip().split("/", 2);
            final byte[] network = literal(parts[0]);
            if (network == null) {
                throw new IllegalStateException("proxy.security.trusted-proxies: '" + entry + "' is not an IP address or CIDR range.");
            }
            final int prefix;
            try {
                prefix = parts.length == 2 ? Integer.parseInt(parts[1]) : network.length * 8;
            } catch (final NumberFormatException e) {
                throw new IllegalStateException("proxy.security.trusted-proxies: '" + entry + "' has an invalid prefix length.");
            }
            if (prefix < 0 || prefix > network.length * 8) {
                throw new IllegalStateException("proxy.security.trusted-proxies: '" + entry + "' has an invalid prefix length.");
            }
            trusted.add(new Cidr(network, prefix));
        }
    }

    public String of(final HttpServletRequest request) {
        final String peer = request.getRemoteAddr();
        if (!isTrusted(peer)) {
            return peer;
        }
        final String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded == null || forwarded.isBlank()) {
            return peer;
        }
        final String[] hops = forwarded.split(",");
        for (int i = hops.length - 1; i >= 0; i--) {
            final String hop = hops[i].strip();
            if (literal(hop) == null) {
                // Not an address: stop rather than believe anything to its left.
                return peer;
            }
            if (!isTrusted(hop)) {
                return hop;
            }
        }
        return peer;
    }

    private boolean isTrusted(final String address) {
        final byte[] bytes = literal(address);
        return bytes != null && trusted.stream().anyMatch(cidr -> cidr.contains(bytes));
    }

    /** The bytes of an IPv4 or IPv6 literal, or null for anything else. Never resolves a host name. */
    static byte[] literal(final String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        final String v = value.startsWith("[") && value.endsWith("]") ? value.substring(1, value.length() - 1) : value;
        final boolean ipv4 = v.matches("\\d{1,3}(\\.\\d{1,3}){3}");
        final boolean ipv6 = v.contains(":") && v.matches("[0-9A-Fa-f:.%a-zA-Z0-9]+");
        if (!ipv4 && !ipv6) {
            return null;
        }
        try {
            return InetAddress.getByName(v).getAddress();
        } catch (final UnknownHostException e) {
            return null;
        }
    }

}
