import Axios from 'axios'
import jsonwebtoken from 'jsonwebtoken'
import { createLogger } from '../../utils/logger.mjs'

const logger = createLogger('auth')

const jwksUrl = 'https://test-endpoint.auth0.com/.well-known/jwks.json'

const certificate = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIJHOda6U4C8tuyMA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
BAMTIWRldi11ZDgwNW5mYnBxMjhjaGFrLnVzLmF1dGgwLmNvbTAeFw0yNDA0Mjgw
NTAyMjFaFw0zODAxMDUwNTAyMjFaMCwxKjAoBgNVBAMTIWRldi11ZDgwNW5mYnBx
MjhjaGFrLnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBALomivApjrgdICS1QhnEz6e/vkAhyoFV6C1UYDE23tqoZNRfXVEnlSntI9eE
qLSo2EjiM4NacZH7DqvYPzmaaSxAj/MGbbhY/fUKDpqrP5hdTe0yj5ykB8hpf/MS
VcPdB8LLQ6d8+Da8GZUQbdkuBlgPHx/R7fZlfn9ZYFeSS5ne4RaHDUYCZyWQPGe9
utiYhVJ/WPkDpTM12OE1aZBQIy7hgPBh6zgN5Qssm//F42qQmdf7XbixOJ0nWCXU
6JKbIAVBAZJIG4P7WavBWTnFbyUo1uQVncwbDNLKvgLRtYiAVrPji4wzbzxNAKw7
BneLwl6c2IHxeGJIb1qMcFo+lRECAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUp8mryLtMnEgVBuGpJRgC/KUw1GYwDgYDVR0PAQH/BAQDAgKEMA0G
CSqGSIb3DQEBCwUAA4IBAQAGAmOT2pxqVadBYzW8T+qzhJIvWenpf3FUXjQSEjzT
1yXEqtE/UO+lVEQBFRfqK5kHoGcf2AkaihT0WI4l4/jdM6netdv9U/57FUOLiobM
YKVONuYed8pv9qvryCpX8J1p3LY5ayjgBRgnZHaB9Khj+gJmVxR9lrLxBlPyKXvQ
fzzpgp7OSvEbRgt/DWM6vnQzgEroufYzVZ9nDKHut39WdiASGWY0gXG1F69G/hJ4
JXQ/jr1H15PBMqG8W4dLMhAfA98698U7gP7afSZTCytPAOS/MA0+OVzMHDNVUJPd
b6fGrjp6FRLRy32OBUeTSLsnPfz8Kjw96BDdkNnRePKm
-----END CERTIFICATE-----`

export async function handler(event) {
  try {
    const jwtToken = await verifyToken(event.authorizationToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader) {
  const token = getToken(authHeader)
  const jwt = jsonwebtoken.decode(token, { complete: true })

  // TODO: Implement token verification
  return jwt
}

function getToken(authHeader) {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
