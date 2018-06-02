import discord
from discord.ext import commands
import asyncio
import configparser
import sys
import traceback

client = commands.Bot(command_prefix='##',
                          description='A utility bot that connects to your GitHub account and links to connected Repos.')

if __name__ == '__main__':
    # use the working directory
    config_file = 'config.ini'

    # use the first parameter if specified
    if len(sys.argv) > 1:
        config_file = sys.argv[1]

    print(f'using the config file: {config_file}')

    # read the config file contents
    cfg = configparser.ConfigParser()
    with open(config_file) as c:
        cfg.read_file(c)

    extensions = ['gitmonitor']

    # load all of the extensions
    for e in extensions:
        try:
            client.load_extension(e)
        except Exception as ex:
            print(f'Failed to load extension {e}', file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

@client.event
async def on_ready():
    # log when the client connects without error
    print(f'Logged in as {client.user.name} - {client.user.id} D.py version {discord.__version__}')
    # set the game status to give a help command
    await client.change_presence(activity=discord.Game('##Help'))

# start the bot
client.run(cfg['Configuration']['connection_token'], bot=True, reconnect=True)