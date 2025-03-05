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
  program
    .name(app.name)
    .version(app.version)

  const exportCommand = program.command('export')
  exportCommand
    .description('Exports to a file a complete month of statements')
    .requiredOption('-k --key <file>', 'Private key file path')
    .option('-m, --month <number>', 'Month to be exported', String(new Date().getMonth()))
    .option('-y, --year <number>', 'Year to be exported', String(new Date().getFullYear()))
    .addOption(new Option('-c, --currency <currency>', 'Currency to be exported').default(''))
    .requiredOption('-o, --output <path>', 'Path to save exported file')
    .addOption(new Option('-t, --type <type>', 'Type of output').default('csv').choices(['csv', 'pdf']))
    .option('-c, --config <path>', 'Custom path for configuration file', configPath)
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

    validateConfig(options.config)

    const numberFormatter = new Intl.NumberFormat(config.locale)
    const dateFormatter = new Intl.DateTimeFormat(config.locale)

    const { month, year, type, key, output, currency } = options
    const selectedMonth = parseInt(month)
    const selectedYear = parseInt(year)

    if (selectedMonth === NaN || selectedMonth < 1 || selectedMonth > 12) {
      throw new Error('Invalid month')
    }

    if (selectedYear === NaN || selectedYear < 2020 || selectedYear > 2100) {
      throw new Error('Invalid year')
    }

    const exportCurrency = (currency === '')? config.currency : currency

    privateKeyPath = path.resolve(key)

    const start = new Date()
    start.setMonth(selectedMonth - 1)
    start.setFullYear(selectedYear)
    start.setUTCDate(1)
    start.setUTCHours(0, 0, 0, 0)

    const end = new Date(start)
    end.setUTCMonth(end.getUTCMonth() + 1)
    start.setFullYear(selectedYear)
    end.setUTCDate(0)
    end.setUTCHours(23, 59, 59, 999)

    log(chalk.gray(`From ${start.toUTCString()} to ${end.toUTCString()}`))
    log('')

    log(chalk.green('Loading profiles...'))
    const profiles = await get('/v2/profiles')
    const profile = profiles.find(p => p.fullName === config.profile)

    log(chalk.green(`Loading balances for ${exportCurrency}...`))
    const balances = await get(`/v3/profiles/${profile.id}/balances?types=STANDARD`)
    const balance = balances.find(b => b.currency === exportCurrency)

    const monthWithPadding = (start.getUTCMonth()+1).toString().padStart(2, "0")
    const outputFileName = output
      .replace('@c@', exportCurrency)
      .replace('@Y@', start.getUTCFullYear())
      .replace('@y@', start.getUTCFullYear()-2000)
      .replace('@m@', monthWithPadding)
      .replace('@t@', type)
    const parsedPath = path.parse(outputFileName)
    const outputDir = (parsedPath.dir === '')? '.' : parsedPath.dir

    if (type === 'csv') {
      log(chalk.green('Loading statments...'))
      const statments = await get(`/v1/profiles/${profile.id}/balance-statements/${balance.id}/statement.json?intervalStart=${start.toISOString()}&intervalEnd=${end.toISOString()}&type=FLAT`)
      const transactions = statments.transactions.map(t => [t.date, t.details.description, t.amount.value])

      log(chalk.green(`Writing "${parsedPath.base}" file into "${outputDir}"...`))
      const stream = fs.createWriteStream(path.resolve(outputFileName))
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
      log(chalk.green(`Downloading "${parsedPath.base}" file into "${outputDir}"...`))
      const pdf = await get(`/v1/profiles/${profile.id}/balance-statements/${balance.id}/statement.pdf?intervalStart=${start.toISOString()}&intervalEnd=${end.toISOString()}&type=FLAT&statementLocale=${config['pdf-locale']}`, true)
      const stream = fs.createWriteStream(path.resolve(outputFileName))
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
