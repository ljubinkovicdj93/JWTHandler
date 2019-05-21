// Project: JWTHandler
//
// Created on Tuesday, May 21, 2019.
// Copyright © 2019 Dorde Ljubinkovic. All rights reserved.

import Foundation

public enum JWTTokenError: Error {
	case invalidTokenUUID
	case invalidJWTToken
	case invalidUserUUID
	case invalidBase64Url(String)
	case incorrectNumberOfComponents(Int)
	case unableToGetJWT
	case unableToEncode
	case unableToGetBody
	case unableToGetHeader
	case unableToGetSignature
}

public protocol JWTClaimRepresentable {
	var aud: [String]? { get }
	var iss: String? { get }
	var sub: String? { get }
	var jti: String? { get }
	var exp: Date? { get }
	var nbf: Date? { get }
	var iat: Date? { get }
}

public struct JWTClaim {
	public enum Key: String, CaseIterable {
		/// iss (issuer): Issuer of the JWT
		case iss
		
		/// sub (subject): Subject of the JWT (the user)
		case sub
		
		/// aud (audience): Recipient for which the JWT is intended
		case aud
		
		/// exp (expiration time): Time after which the JWT expires
		case exp
		
		/// nbf (not before time): Time before which the JWT must not be accepted for processing
		case nbf
		
		/// iat (issued at time): Time at which the JWT was issued; can be used to determine age of the JWT
		case iat
		
		/// jti (JWT ID): Unique identifier; can be used to prevent the JWT from being replayed (allows a token to be used only once)
		case jti
	}
	
	subscript(claimKey: JWTClaim.Key) -> Any? {
		get {
			switch claimKey {
			case .aud:
				return self.stringArray
				
			case .iss, .sub, .jti:
				return self.string
				
			case .exp, .nbf, .iat:
				return self.date
			}
		}
	}
	
	/// raw value of the claim
	let rawValue: Any?
	
	/// original claim value
	public var value: Any? {
		return self.rawValue
	}
	
	/// value of the claim as `String`
	public var string: String? {
		return self.rawValue as? String
	}
	
	/// value of the claim as `Double`
	public var double: Double? {
		let double: Double?
		if let string = self.string {
			double = Double(string)
		} else {
			double = self.rawValue as? Double
		}
		return double
	}
	
	/// value of the claim as `Int`
	public var integer: Int? {
		let integer: Int?
		if let string = self.string {
			integer = Int(string)
		} else if let double = self.rawValue as? Double {
			integer = Int(double)
		} else {
			integer = self.rawValue as? Int
		}
		return integer
	}
	
	/// value of the claim as `Date`
	public var date: Date? {
		guard let timestamp: TimeInterval = self.double else { return nil }
		return Date(timeIntervalSince1970: timestamp)
	}
	
	/// value of the claim as `[String]`
	public var stringArray: [String]? {
		if let array = self.rawValue as? [String] {
			return array
		}
		if let value = self.string {
			return [value]
		}
		return nil
	}
}

public struct JWTHeader: Codable {
	let alg: String
	let typ: String
	let kid: String?
}

public protocol JWTTokenRepresentable {
	associatedtype Payload: Codable
	
	/// token header part contents
	var header: JWTHeader { get }
	
	/// token body part values or token claims
	var body: Payload { get }
	
	/// token signature part
	var signature: String? { get }
	
	/// jwt string value
	var string: String { get }
	
	/// jwt claims
	var claims: [JWTClaim] { get }
}

public final class JWTToken<Payload: NSObject & Codable & JWTClaimRepresentable>: JWTTokenRepresentable {
	
	public var header: JWTHeader
	public var body: Payload
	public var string: String
	public var signature: String?

	public var claims: [JWTClaim] = []
	
	init(header: JWTHeader, body: Payload, signature: String?, string: String) {
		self.header = header
		self.body = body
		self.signature = signature
		self.string = string
		
		self.setClaims(from: self.body)
	}
	
	func setClaims(from body: Payload) {
		let mirrorDict = Mirror(reflecting: body)
		
		JWTClaim.Key.allCases.forEach { claimKey in
			mirrorDict.children.forEach {
				if $0.label == claimKey.rawValue {
					guard let value = mirrorDict.descendant(claimKey.rawValue) else { fatalError("Something is not right.") }
					self.claims.append(JWTClaim(rawValue: value))
				}
			}
		}
	}
	
	public func getClaimValue(_ claimKey: JWTClaim.Key) -> Any? {
		switch claimKey {
		case .aud:
			return self.body.aud
		case .iss:
			return self.body.iss
		case .sub:
			return self.body.sub
		case .jti:
			return self.body.jti
		case .exp:
			return self.body.exp
		case .nbf:
			return self.body.nbf
		case .iat:
			return self.body.iat
		}
	}
}

public protocol JWTTokenHandleProtocol {
	associatedtype Payload: NSObject & Codable & JWTClaimRepresentable
	
	var jwtToken: JWTToken<Payload>? { get set }
	func getJwtHeader() throws -> JWTHeader
	func getJwtBody() throws -> Payload
	func getJwtSignature() throws -> String?
	
	func decodeJWT(_ jwtString: String) throws -> JWTToken<Payload>
	func getJWTComponents(_ jwtString: String) throws -> (header: JWTHeader, payload: Payload, signature: String?)
}

extension JWTTokenHandleProtocol {
	public func getJwtHeader() throws -> JWTHeader {
		guard let jwt = self.jwtToken else {
			throw JWTTokenError.unableToGetJWT
		}
		do {
			let components = try getJWTComponents(jwt.string)
			return components.header
		} catch {
			throw JWTTokenError.unableToGetHeader
		}
	}
	
	public func getJwtBody() throws -> Payload {
		guard let jwt = self.jwtToken else {
			throw JWTTokenError.unableToGetJWT
		}
		do {
			let components = try getJWTComponents(jwt.string)
			return components.payload
		} catch {
			throw JWTTokenError.unableToGetBody
		}
	}
	
	public func getJwtSignature() throws -> String? {
		guard let jwt = self.jwtToken else {
			throw JWTTokenError.unableToGetJWT
		}
		do {
			let components = try getJWTComponents(jwt.string)
			return components.signature
		} catch {
			throw JWTTokenError.unableToGetSignature
		}
	}
	
	public func getJWTComponents(_ jwtString: String) throws -> (header: JWTHeader, payload: Payload, signature: String?) {
		let components = jwtString.components(separatedBy: ".")
		guard components.count == 3 else {
			throw JWTTokenError.incorrectNumberOfComponents(components.count)
		}
		
		guard let header = try decodeJWTPart(JWTHeader.self, components[0]) else { fatalError("Can't parse json.") }
		guard let body = try decodeJWTPart(Payload.self, components[1]) else { fatalError("Can't parse json.") }
		let signature = components[2]
		
		return (header: header, payload: body, signature: signature)
	}
	
	public func decodeJWT(_ jwtString: String) throws -> JWTToken<Payload> {
		do {
			let components = try getJWTComponents(jwtString)
			
			let jwtToken = JWTToken(header: components.header,
									body: components.payload,
									signature: components.signature,
									string: jwtString)
			jwtToken.setClaims(from: components.payload)
			
			return jwtToken
		} catch {
			fatalError(error.localizedDescription)
		}
	}
}

fileprivate func base64UrlDecode(_ value: String) -> Data? {
	var base64 = value
		.replacingOccurrences(of: "-", with: "+")
		.replacingOccurrences(of: "_", with: "/")
	let length = Double(base64.lengthOfBytes(using: String.Encoding.utf8))
	let requiredLength = 4 * ceil(length / 4.0)
	let paddingLength = requiredLength - length
	if paddingLength > 0 {
		let padding = "".padding(toLength: Int(paddingLength), withPad: "=", startingAt: 0)
		base64 += padding
	}
	return Data(base64Encoded: base64, options: .ignoreUnknownCharacters)
}

fileprivate func decodeJWTPart<Model: Decodable>(_ type: Model.Type, _ value: String) throws -> Model? {
	guard let bodyData = base64UrlDecode(value) else {
		throw JWTTokenError.invalidBase64Url(value)
	}
	
	do {
		let payload: Model = try JSONDecoder().decode(type.self, from: bodyData)
		return payload
	} catch {
		throw JWTTokenError.invalidJWTToken
	}
}


