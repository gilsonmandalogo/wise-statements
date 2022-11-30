# wise-statements

It's an app to retrieve a complete month of statements from [Wise](https://wise.com/) and export it to a CSV or PDF file.

## Usage

First you need to configure the following things:

| Config | Description | Example |
| ------ | ----------- | ------- |
| api-token | Get [here](https://wise.com/settings/api-tokens) a read-only token |
| profile | Account owner's name |
| locale | For number and date formating | pt-PT |
| pdf-locale | Language of the exported PDF document | pt |
| currency | Currency account to export | EUR |

Use the following command to set each config: `wise-statements config <name> <value>`.

You also will need a pair of public/private keys, you can follow [this link](https://wise.com/public-keys) to create one.

After that you are ready to use the `export` command, if you need any more details you can print all available help with `wise-statements -h`.
