#!/usr/bin/env node

import fs from 'fs'
import path from 'path'
import os from 'os'
import url from 'url'
import fetch from 'node-fetch'
import chalk from 'chalk'
import crypto from 'crypto'
import * as jose from 'jose'
import { program, Option } from 'commander'

const log = console.log
const baseUrl = 'https://api.transferwise.com'
const config = {}
const dirname = path.dirname(url.fileURLToPath(import.meta.url))
const app = JSON.parse(fs.readFileSync(path.resolve(dirname, 'package.json'), 'utf-8'))
const appPath = path.resolve(os.homedir(), '.config', app.name)
const configPath = path.resolve(appPath, '.config.json')

let publicKey = null
// let privateKey = null
let cachedDeviceFingerprint = null

async function generateRsaKeyPair() {
  log(chalk.green('Creating a new RSA key pair.'));

  const keyPair = await jose.generateKeyPair('RSA-OAEP-256', {
    modulusLength: 2048,
  })
  publicKey = keyPair.publicKey
  // privateKey = keyPair.privateKey

  const publicJwk = await jose.exportJWK(publicKey)
  // const privateJwk = await jose.exportJWK(privateKey)

  fs.writeFileSync('public_key.json', JSON.stringify(publicJwk, null, 2))
  // fs.writeFileSync('private_key.json', JSON.stringify(privateJwk, null, 2))

  log(chalk.green('RSA key pair generated.'))
  
  await postClientPublicKey(publicJwk)
}

async function postClientPublicKey(publicJwk) {
  // Convert the JWK to a Node.js compatible key format
  const publicKey = crypto.createPublicKey({
    key: {
      kty: publicJwk.kty,
      n: publicJwk.n,
      e: publicJwk.e,
    },
    format: 'jwk',
  })
  
  const derPublicKey = publicKey.export({
    type: 'spki',
    format: 'der',
  })
  
  // Convert to base64
  const base64DerPublicKey = derPublicKey.toString('base64')

  try {
    const response = await fetch(`${baseUrl}/v1/auth/jose/request/public-keys`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${config['api-token']}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        // validFrom: new Date().toISOString(),
        scope: 'PAYLOAD_ENCRYPTION',
        publicKeyMaterial: {
          algorithm: 'RSA_OAEP_256',
          keyMaterial: base64DerPublicKey,
        },
      }),
    })

    if (!response.ok) {
      const body = await response.text()
      throw new Error(`Wise API returned ${response.status}: ${response.statusText}\n${body}`)
    }

    const body = await response.json()
    log(chalk.green(`Public key posted to the API. Valid until ${body.validTill}.`))
  } catch (error) {
    log(chalk.red('Error while trying to post public key to the API.'))
    throw error
  }
}

async function encryptWithJwe(payload) {
  // Check for publicKey and load or generate new key pair if needed
  if (!publicKey) {
    if (fs.existsSync('public_key.json')) {
      log(chalk.green('Loading existing RSA public key.'))
      const publicJwk = JSON.parse(fs.readFileSync('public_key.json', 'utf-8'))
      publicKey = await jose.importJWK(publicJwk, 'RSA-OAEP-256')
    } else {
      await generateRsaKeyPair()
    }
  }

  // Create a JWE using RSA-OAEP-256 for key encryption
  const jwe = await new jose.CompactEncrypt(
    new TextEncoder().encode(JSON.stringify(payload)),
  )
    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
    .encrypt(publicKey)

  return jwe
}

function generateDeviceFingerprint() {
  if (cachedDeviceFingerprint) {
    return cachedDeviceFingerprint
  }

  // Collect system-specific attributes
  const osType = os.type() // e.g., 'Linux'
  const osRelease = os.release() // e.g., '5.15.0-60-generic'
  const cpuArch = os.arch() // e.g., 'x64'
  const hostname = os.hostname() // e.g., 'my-computer'
  const userInfo = os.userInfo().username // e.g., 'john'
  const networkInterfaces = os.networkInterfaces()

  // Extract MAC addresses from network interfaces
  const macAddresses = Object.values(networkInterfaces)
    .flat()
    .filter((iface) => iface && !iface.internal && iface.mac)
    .map((iface) => iface.mac)
    .join(',')

  // Concatenate attributes into a single string
  const fingerprintData = `${osType}-${osRelease}-${cpuArch}-${hostname}-${userInfo}-${macAddresses}`

  // Hash the concatenated string using SHA-256
  const hash = crypto.createHash('sha256').update(fingerprintData).digest('hex')

  // Cache the fingerprint for future use
  cachedDeviceFingerprint = hash

  return hash
}

async function createDeviceFingerprint(options) {
  log(chalk.underline(`${app.name} v${app.version}`))
  log('')

  validateConfig(options.config)

  try {
    const response = await fetch(`${baseUrl}/v1/auth/jose/request/device-fingerprint`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${config['api-token']}`,
        'Content-Type': 'application/jose+json',
        'X-TW-JOSE-Method': 'jwe',
        'Accept': 'application/jose+json',
        'Accept-Encoding': '*',
      },
      body: await encryptWithJwe({
        deviceFingerprint: generateDeviceFingerprint(),
      }),
    })

    if (!response.ok) {
      const body = await response.text()
      throw new Error(`Wise API returned ${response.status}: ${response.statusText}\n${body}`)
    }

    log(chalk.green('Device fingerprint created.'))
  } catch (error) {
    log(chalk.red('Error while trying to create device fingerprint.'))
    throw error
  }
}

function doSCA() {
  
}

async function get(path, returnStream, headers) {
  try {
    const response = await fetch(`${baseUrl}${path}`, {
      headers: {
        'Authorization': `Bearer ${config['api-token']}`,
        ...headers,
      }
    })

    if (response.status === 403 && response.headers.get('x-2fa-approval-result') === 'REJECTED') {
      const ott = response.headers.get('x-2fa-approval')
      await getOTTStatus(ott)
      return await get(path, returnStream, {
        'x-2fa-approval': token,
        'X-Signature': await doSCA(token),
      })
    }

    if (!response.ok) {
      const body = await response.text()
      throw new Error(`Wise API returned ${response.status}: ${response.statusText}\n${body}`)
    }

    if (returnStream) {
      return response.body
    }

    return await response.json()
  } catch (error) {
    if (!headers) {
      log(chalk.red(`Error while trying to fetch ${baseUrl}${path}\n${error}`))
    }

    throw error
  }
}

async function getOTTStatus(ott) {
  try {
    const response = await fetch(`${baseUrl}/v1/identity/one-time-token/status`, {
      headers: {
        'Authorization': `Bearer ${config['api-token']}`,
        'One-Time-Token': ott,
      }
    })

    if (!response.ok) {
      const body = await response.text()
      throw new Error(`Wise API returned ${response.status}: ${response.statusText}\n${body}`)
    }

    const ottResponse = await response.json()
    
    if (ottResponse.oneTimeTokenProperties.challenges.length > 0) {
      log(chalk.yellow(`Challenges left to have an approved OTT: ${ottResponse.oneTimeTokenProperties.challenges.length}.`))
    }

    log(ottResponse.oneTimeTokenProperties.challenges[0].primaryChallenge)
    throw new Error('Under construction')
  } catch (error) {
    log(chalk.red('Error while trying to get OTT status'))
    throw error
  }
}

function main() {
  program
    .name(app.name)
    .version(app.version)

  const exportCommand = program.command('export')
  exportCommand
    .description('Exports to a file a complete month of statements')
    .option('-m, --month <number>', 'Month to be exported', String(new Date().getMonth()))
    .requiredOption('-o, --output <path>', 'Path to save exported file')
    .addOption(new Option('-t, --type <type>', 'Type of output').default('csv').choices(['csv', 'pdf']))
    .option('-c, --config <path>', 'Custom path for configuration file', configPath)
    .action(exportFile)

  const configCommand = program.command('config <name> [value]')
  configCommand
    .description('Read or set a configuration')
    .action(configAction)

  const deviceFingerprintCommand = program.command('create-device-fingerprint')
  deviceFingerprintCommand
    .description('Creates a device fingerprint')
    .option('-c, --config <path>', 'Custom path for configuration file', configPath)
    .action(createDeviceFingerprint)

  program.parse()
}

async function exportFile(options) {
  try {
    log(chalk.underline(`${app.name} v${app.version}`))
    log('')

    validateConfig(options.config)

    const numberFormatter = new Intl.NumberFormat(config.locale)
    const dateFormatter = new Intl.DateTimeFormat(config.locale)

    const { month, type, output } = options
    const selectedMonth = parseInt(month)

    if (selectedMonth === NaN) {
      throw new Error('Invalid month')
    }

    const start = new Date()
    start.setMonth(selectedMonth - 1)
    start.setUTCDate(1)
    start.setUTCHours(0, 0, 0, 0)

    const end = new Date(start)
    end.setUTCMonth(end.getUTCMonth() + 1)
    end.setUTCDate(0)
    end.setUTCHours(23, 59, 59, 999)

    log(chalk.gray(`From ${start.toUTCString()} to ${end.toUTCString()}`))
    log('')

    log(chalk.green('Loading profiles...'))
    const profiles = await get('/v2/profiles')
    const profile = profiles.find(p => p.fullName === config.profile)

    log(chalk.green('Loading balances...'))
    const balances = await get(`/v3/profiles/${profile.id}/balances?types=STANDARD`)
    const balance = balances.find(b => b.currency === config.currency)

    const parsedPath = path.parse(output)

    if (type === 'csv') {
      log(chalk.green('Loading statments...'))
      const statments = await get(`/v1/profiles/${profile.id}/balance-statements/${balance.id}/statement.json?intervalStart=${start.toISOString()}&intervalEnd=${end.toISOString()}&type=FLAT`)
      const transactions = statments.transactions.map(t => [t.date, t.details.description, t.amount.value])

      log(chalk.green(`Writing "${parsedPath.base}" file into "${parsedPath.dir}"...`))
      const stream = fs.createWriteStream(path.resolve(output))
      stream.once('open', () => {
        stream.write('DATA;;\n')

        for (const transaction of transactions) {
          let signal = ''
          const line = transaction.map((t, i) => {
            if (typeof t === 'number') {
              signal = t < 0 ? '"D"' : '"C"'
              return numberFormatter.format(t)
            }
            if (i === 0) {
              return dateFormatter.format(new Date(t))
            }
            return `"${t}"`;
          })
          line.push(signal)
          stream.write(`${line.join(';')}\n`)
        }
        stream.end()
      })
    }

    if (type === 'pdf') {
      log(chalk.green(`Downloading "${parsedPath.base}" file into "${parsedPath.dir}"...`))
      const pdf = await get(`/v1/profiles/${profile.id}/balance-statements/${balance.id}/statement.pdf?intervalStart=${start.toISOString()}&intervalEnd=${end.toISOString()}&type=FLAT&statementLocale=${config['pdf-locale']}`, true)
      const stream = fs.createWriteStream(path.resolve(output))
      await new Promise((resolve, reject) => {
        pdf.pipe(stream);
        pdf.on('error', reject);
        stream.on('finish', resolve);
      })
    }

    log(chalk.bold.green('Done, enjoy your saved time!'))
  } catch (error) {
    log('')

    if (error instanceof Error) {
      log(`${error.name}: ${error.message}`)
      log(error.stack)
    } else {
      log(error)
    }

    log(chalk.red('Program exited due to error. 😢'))
    process.exitCode = 1
  }
}

function validateConfig(configPath) {
  const file = fs.readFileSync(path.resolve(configPath), 'utf-8')
  const parsed = JSON.parse(file)
  const keys = ['api-token', 'profile', 'locale', 'pdf-locale', 'currency']

  for (const key of keys) {
    if (!parsed[key]) {
      throw new Error(`${key} is missing on configuration`)
    }
  }

  Object.assign(config, parsed)
}

function configAction(name, value) {
  fs.mkdirSync(appPath, { recursive: true })

  if (!fs.existsSync(configPath)) {
    fs.writeFileSync(configPath, '{}', 'utf-8')
  }

  const file = fs.readFileSync(configPath, 'utf-8')
  const parsed = JSON.parse(file)

  if (value) {
    parsed[name] = value
    fs.writeFileSync(configPath, JSON.stringify(parsed, null, 2), 'utf-8')
  } else {
    log(parsed[name])
  }
}

main()
