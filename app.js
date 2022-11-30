#!/usr/bin/env node

import fs from 'fs'
import path from 'path'
import os from 'os'
import url from 'url'
import fetch from 'node-fetch'
import chalk from 'chalk'
import crypto from 'crypto'
import { program, Option } from 'commander'

const log = console.log
const baseUrl = 'https://api.transferwise.com'
const config = {}
const dirname = path.dirname(url.fileURLToPath(import.meta.url))
const app = JSON.parse(fs.readFileSync(path.resolve(dirname, 'package.json'), 'utf-8'))
const appPath = path.resolve(os.homedir(), '.config', app.name)
const configPath = path.resolve(appPath, '.config.json')

let privateKeyPath = ''

function do2FA(token) {
  const key = fs.readFileSync(privateKeyPath)
  const signature = crypto.sign("sha256", Buffer.from(token), {
    key,
  });

  return signature.toString('base64')
}

async function get(path, returnStream, headers) {
  try {
    const response = await fetch(`${baseUrl}${path}`, {
      headers: {
        'Authorization': `Bearer ${config['api-token']}`,
        ...headers,
      }
    })

    if (!headers && response.status === 403 && response.headers.has('x-2fa-approval')) {
      log(chalk.gray('Signing OTT...'))
      const token = response.headers.get('x-2fa-approval')
      return await get(path, returnStream, {
        'x-2fa-approval': token,
        'X-Signature': await do2FA(token),
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

function main() {
  fs.mkdirSync(appPath, { recursive: true })

  if (!fs.existsSync(configPath)) {
    fs.writeFileSync(configPath, '{}', 'utf-8')
  }

  program
    .name(app.name)
    .version(app.version)

  const exportCommand = program.command('export')
  exportCommand
    .description('Exports to a file a complete month of statements')
    .requiredOption('-k --key <file>', 'Private key file path')
    .requiredOption('-m, --month <number>', 'Month to be exported')
    .requiredOption('-o, --output <directory>', 'Directory to save exported files')
    .addOption(new Option('-t, --type <type>', 'Type of output').default('csv').choices(['csv', 'pdf']))
    .action(exportFile)

  const configCommand = program.command('config <name> [value]')
  configCommand
    .description('Read or set a configuration')
    .action(configAction)

  program.parse()
}

const exportFile = async (options) => {
  try {
    log(chalk.underline(`${app.name} v${app.version}`))
    log('')

    validateConfig()

    const numberFormatter = new Intl.NumberFormat(config.locale)
    const dateFormatter = new Intl.DateTimeFormat(config.locale)

    const { month, type, key, output } = options
    const selectedMonth = parseInt(month)

    if (selectedMonth === NaN) {
      throw new Error('Invalid month')
    }

    privateKeyPath = path.resolve(key)

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

    if (type === 'csv') {
      log(chalk.green('Loading statments...'))
      const statments = await get(`/v1/profiles/${profile.id}/balance-statements/${balance.id}/statement.json?intervalStart=${start.toISOString()}&intervalEnd=${end.toISOString()}&type=FLAT`)
      const transactions = statments.transactions.map(t => [t.date, t.details.description, t.amount.value])

      log(chalk.green('Writing CSV file...'))
      const stream = fs.createWriteStream(path.resolve(output, `${start.getUTCMonth() + 1}.csv`))
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
      log(chalk.green('Downloading PDF...'))
      const pdf = await get(`/v1/profiles/${profile.id}/balance-statements/${balance.id}/statement.pdf?intervalStart=${start.toISOString()}&intervalEnd=${end.toISOString()}&type=FLAT&statementLocale=${config['pdf-locale']}`, true)
      const stream = fs.createWriteStream(path.resolve(output, `${start.getUTCMonth() + 1}.pdf`))
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

function validateConfig() {
  const file = fs.readFileSync(configPath, 'utf-8')
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
