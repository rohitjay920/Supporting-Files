package com.project.github;


import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetails;

import com.project.entity.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

public class JwtFilter {
	private String secret = "dsjbviuahviufahdvblfvbuiafbvlnvbsbdvliHASUVHSABHUHFIUeshfilghwiuvhviubdsvuin";
	private Long expirationDate = 30*60*60*1000l;
	
	public String generateToken(UserDetails userDetails) {
		HashMap<String,Object> hs = new HashMap();
		hs.put("user_name", userDetails.getUsername());
		hs.put("user_role",((User)userDetails).getRole());
		return generateToken(userDetails, hs);
	}
	
	public String generateToken(UserDetails userDetails, HashMap<String,Object> extraClaims) {
		return Jwts.builder().setClaims(extraClaims).setSubject(((User)userDetails).getEmail())
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + expirationDate))
				.signWith(getSigningKey(), SignatureAlgorithm.HS256).compact();
	}
	
	public Key getSigningKey() {
		byte[] keyBytes = Decoders.BASE64.decode(secret);
		return Keys.hmacShaKeyFor(keyBytes);
	}
	
	private Date extractExpiration(String jwt) {
		return extractClaim(jwt, Claims::getExpiration);
	}
	
	private Claims extractAllClaims(String jwt) {
		return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(jwt).getBody();
	}
	
	private boolean isTokenExpired(String jwt) {
		return extractExpiration(jwt).after(new Date());
	}
	
	private <T> T extractClaim(String jwt, Function<Claims, T> claimsResolvers) {
		final Claims claims = extractAllClaims(jwt);
		return claimsResolvers.apply(claims);
	}
	
	public boolean isTokenValid(String jwt, UserDetails details) {
		String userName = extractUserName(jwt);
		System.err.println(userName+"  in jwt");
		System.err.println(details.getUsername()+"  in details");
//		System.err.println(userName.equals(details.getUsername())+"   from jwtutils");
		return (userName.equals(((User)details).getEmail()) && isTokenExpired(jwt));
	}
	
	public String extractUserName(String jwt) {
		return extractClaim(jwt, Claims::getSubject);
	}
}
