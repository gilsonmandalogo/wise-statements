const baseUrl = 'https://api.transferwise.com'
/** @type {import('node-fetch').default} */
let fetch = null
/** @type {import('chalk').default} */
let chalk = null
/** @type {import('fs')} */
let fs = null

const log = console.log

function do2FA(token) {
  const crypto = require('crypto')

  const key = fs.readFileSync('./private.pem')
  const signature = crypto.sign("sha256", Buffer.from(token), {
    key,
  });

  return signature.toString('base64')
}

async function get(path, headers) {
  try {
    const response = await fetch(`${baseUrl}${path}`, {
      headers: {
        'Authorization': `Bearer ${process.env.API_TOKEN}`,
        ...headers,
      }
    })

    if (!headers && response.status === 403 && response.headers.has('x-2fa-approval')) {
      log(chalk.gray('Signing OTT...'))
      const token = response.headers.get('x-2fa-approval')
      return await get(path, {
        'x-2fa-approval': token,
        'X-Signature': await do2FA(token),
      })
    }

    if (!response.ok) {
      const body = await response.text()
      throw new Error(`Wise API returned ${response.status}: ${response.statusText}\n${body}`)
    }

    return await response.json()
  } catch (error) {
    if (!headers) {
      log(chalk.red(`Error while trying to fetch ${baseUrl}${path}\n${error}`))
    }

    throw error
  }
}

async function main() {
  const app = require('./package.json')
  require('dotenv').config()
  chalk = (await import('chalk')).default
  fetch = (await import('node-fetch')).default
  fs = (await import('fs')).default
  const prompt = require('prompt-sync')({ sigint: true })
  const numberFormatter = new Intl.NumberFormat(process.env.LOCALE)
  const dateFormatter = new Intl.DateTimeFormat(process.env.LOCALE)

  try {
    log(chalk.underline(`${app.name} v${app.version}`))
    log('')

    const start = new Date()

    const defaultAnswer = start.getMonth() + 1
    const selectedMonth = parseInt(prompt(`${chalk.bold('Which month do you want to export?')} [${defaultAnswer}] `, defaultAnswer))

    if (selectedMonth === NaN) {
      throw new Error('Invalid input')
    }

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
    const profile = profiles.find(p => p.fullName === process.env.PROFILE_NAME)

    log(chalk.green('Loading balances...'))
    const balances = await get(`/v3/profiles/${profile.id}/balances?types=STANDARD`)
    const balance = balances.find(b => b.currency === 'EUR')

    log(chalk.green('Loading statments...'))
    const statments = await get(`/v1/profiles/${profile.id}/balance-statements/${balance.id}/statement.json?intervalStart=${start.toISOString()}&intervalEnd=${end.toISOString()}&type=FLAT`)
    const transactions = statments.transactions.map(t => [t.date, t.details.description, t.amount.value])

    log(chalk.green('Writing CSV file...'))
    const stream = fs.createWriteStream(`./${start.getUTCMonth() + 1}.csv`)
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

    log(chalk.bold.green('Done, enjoy your saved time!'))
  } catch (error) {
    log('')
    log(chalk.red('Program exited due to error. 😢'))
  }
}

main()
