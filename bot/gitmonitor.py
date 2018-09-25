from typing import Union

import discord
from discord.ext import commands
import re
import sqlite3
from github import Github, Repository, Issue, PullRequest, UnknownObjectException, Commit
import secrets
import datetime
import requests
import sys
import time
import configparser
import os.path

startTime = time.time()


async def only_dm(ctx):
    return ctx.guild is None and isinstance(discord.DMChannel, ctx.channel)


class GitMonitor:

    def __init__(self, bot):
        print('Setting up the Git Commands.')
        self.bot = bot

        config_file = '/app/data/config.ini'
        database_file = '/app/data/database.db'
        if len(sys.argv) > 2:
            config_file = sys.argv[1]
            database_file = sys.argv[2]

        print(f'using the config file: {config_file} and database file: {database_file}')

        if not os.path.isfile(config_file):
            print('ERROR: config file does not exist')
        if not os.path.isfile(database_file):
            print('ERROR: database file does not exist')

        self.auth_database_file = database_file

        self.cfg = configparser.ConfigParser()
        with open(config_file) as c:
            self.cfg.read_file(c)

        # debug
        for section in self.cfg.sections():
            print(section, dict(self.cfg[section]))

        print(f'callback endpoint {self.cfg["Login"]["github_login_callback"]}')
        print(f'redirect endpoint {self.cfg["Login"]["github_login_redirect"]}')

        self.user_auth_db = sqlite3.connect(self.auth_database_file, check_same_thread=False)

    @commands.command()
    @commands.cooldown(5, 60, commands.BucketType.user)
    async def ping(self, ctx):
        await ctx.send(f'Pong! Uptime: {(time.time() - startTime)}')

    def get_user_login_token(self, userId: int) -> str:
        """
        Gets a user login token
        :param userId:
        :return:
        """
        # generate a secret with 128 bytes
        token = secrets.token_urlsafe(128)
        # create an expiration time 5 minutes from now
        expiration_time = datetime.datetime.now() + datetime.timedelta(minutes=5)

        # remove any existing login tokens from the table
        c = self.user_auth_db.cursor()
        c.execute(
            '''
            DELETE FROM UserLogin WHERE DiscordUserId = ?;
            ''',
            (userId, )
        )

        # insert a new row into the login table
        c.execute(
            '''
            INSERT INTO UserLogin (DiscordUserId, Token, Expiration)
            VALUES (?, ?, ?);
            ''',
            (userId, token, expiration_time)
        )
        self.user_auth_db.commit()

        # return the token so that we can make the login url
        return token

    def get_login_url(self, token) -> str:
        args = {
            'token': token
        }

        login_redirect = self.cfg['Login']['github_login_redirect']

        return requests.Request('GET', login_redirect, params=args).prepare().url

    @commands.command()
    @commands.bot_has_permissions(send_messages=True)
    @commands.cooldown(5, 60, commands.BucketType.user)
    async def me(self, ctx):
        """
        Gets the connected GitHub account
        :param ctx:
        :return:
        """
        token = self.get_authorization_for_context(ctx.author.id)

        if token is None:
            await ctx.send('You are not logged in.')
        else:
            print('token', token)
            g = Github(token)
            user = g.get_user().login

            await ctx.send(f'You are logged in as github user **{user}**.')

    @commands.command()
    async def login(self, ctx):
        """
        Sends the user a unique login url just for them that will expire in 5 minutes
        :param ctx:
        :return:
        """
        if ctx.guild is not None:
            try:
                # try to DM the user
                if ctx.author.dm_channel is None:
                    await ctx.author.create_dm()
                await ctx.author.dm_channel.send('The login command can only be used in a direct message, because it ' +
                                           'contains private information. Execute this command again.')

                await ctx.send('This command does not work in a server. Check your DMs.')
            except discord.DiscordException:
                # failed to send DM
                    await ctx.send('This command does not work in a server. DM the command to me.')
        elif isinstance(ctx.channel, discord.DMChannel):
            login_discord_user = ctx.author.id
            token = self.get_user_login_token(login_discord_user)
            url = self.get_login_url(token)

            # print(f'generated the new token {token} for user {login_discord_user}')'
            gh_client_id = self.cfg['GitHub']['client_id']

            revoke_url = f'https://github.com/settings/connections/applications/{gh_client_id}'

            message = f"Here's your unique login url:\n" \
                      f'\n<{url}>\n\n' \
                      f'**!!! Keep this URL safe !!!**\n' \
                      f'\n' \
                      f'This URL is specifically tied to your Discord account. It will expire in 5 minutes,' \
                      f' or after it is used once, whichever comes first.' \
                      f'\n\n' \
                      f'If you wish to invalidate this url, you may use the `##login` command again.\n\n' \
                      f"If you wish to revoke this application's access to your GitHub account, you may do so" \
                      f" with the following link: {revoke_url}\n" \
                      f"" \
                      f"You can check to see if you were authorized successfully with the `##me` command. '"
            await ctx.send(message)

    #TODO: add unlink channel, guild, and me commands

    def get_github_repo_for_context(self, userId, channelId, guildId) -> str:
        """
        Gets the github repo for the given context
        :param userId:
        :param channelId:
        :param guildId:
        :return:
        """
        print('Getting gh repo for user', userId, 'channel', channelId, 'guild', guildId)
        c = self.user_auth_db.cursor()

        # first get link_channel authored by current user
        c.execute('''
            SELECT RepoName FROM LinkChannels
            WHERE GuildId = ? AND ChannelId = ? AND AuthorDiscordUserId = ?;
        ''', (guildId, channelId, userId, ))
        result = c.fetchone()
        if result is not None:
            return result[0]

        # get link_channel
        c.execute('''
                    SELECT RepoName FROM LinkChannels
                    WHERE GuildId = ? AND ChannelId = ?;
                ''', (guildId, channelId, ))
        result = c.fetchone()
        if result is not None:
            return result[0]

        # ignore when channel id is 0
        if guildId != 0:
            # get link_me exclusive
            c.execute('''
                SELECT RepoName FROM LinkGuilds
                WHERE GuildId = ? AND AuthorDiscordUserId = ? AND AuthorOnly = 1;
                ''', (guildId, userId,))
            result = c.fetchone()
            if result is not None:
                return result[0]

            # get link_guild by user
            c.execute('''
                SELECT RepoName FROM LinkGuilds
                WHERE GuildId = ? AND AuthorDiscordUserId = ? AND AuthorOnly = 0;
                ''', (guildId, userId,))
            result = c.fetchone()
            if result is not None:
                return result[0]

        # get link_guild
        c.execute('''
            SELECT RepoName FROM LinkGuilds
            WHERE GuildId = ? AND AuthorOnly = 0;
            ''', (guildId, ))
        result = c.fetchone()
        if result is not None:
            return result[0]

    def get_authorization_for_context(self, user_id: int):
        """
        Gets the authorization for the user to log in
        :param user_id:
        :return:
        """
        c = self.user_auth_db.cursor()
        # get the authorization token for the user
        c.execute(
            '''SELECT GithubAuthorizationToken FROM UserGithubAuthorization WHERE DiscordUserId = ?;
            ''', (user_id,))
        result = c.fetchone()
        if result is None:
            return None
        # return the token for the user
        return result[0]
        # import configparser
        #
        # # read the config file contents
        # cfg = configparser.ConfigParser()
        # with open('../config.ini') as c:
        #     cfg.read_file(c)
        # return cfg['Debug']['github_auth']

    async def on_command_error(self, ctx, error):
        print(f'Command error {error}')
        # do nothing, we are expecting many errors, so fail silently
        pass

    async def on_message(self, message):
        """
        Listens for when the user has used the

        ##PR ##Issue ##hash ##branch

        syntax in their message, and call the appropriate
        methods when they do

        :param message:
        :return:
        """
        if message.author.id == self.bot.user.id:
            # print('Message author was same as bot user id')
            return
        # get the repo for the context
        author_id = message.author.id
        channel_id = message.channel.id
        guild_id = 0
        if message.guild is not None:
            guild_id = message.guild.id

        repo = self.get_github_repo_for_context(author_id, channel_id, guild_id)

        if repo is None:
            # print('couldnt find associated repo')
            return

        auth = self.get_authorization_for_context(author_id)

        if auth is None:
            # use no token
            # this will be ratelimited and not have access to private repos
            # print('no auth token, may be rate limited')
            gh = Github()
        else:
            # login with the access token
            gh = Github(auth)

        r = gh.get_repo(repo)

        use_embeds = True

        for x in regex_matches_pr_or_issue(message.content):
            # trim off the ## leading
            num = x.group()[2:]
            # convert to an int
            num = int(num)

            # print(f'PR/Issue {num}')

            try:
                # get the issue for the repo
                issue = r.get_issue(num)

                if issue is None:
                    # print('error')
                    pass
                else:
                    if issue.pull_request is not None:
                        # pull request
                        pr = issue.as_pull_request()
                        # print('pull request', pr)
                        if use_embeds:
                            await self.send_pullrequest_embed(issue, pr, message.channel)
                        else:
                            await self.send_pullrequest_message(issue, pr, message.channel)
                    else:
                        # print('issue', issue)
                        if use_embeds:
                            await self.send_issue_embed(issue, message.channel)
                        else:
                            await self.send_issue_message(issue, message.channel)
            except UnknownObjectException:
                # pr/issue number probably doesn't exist
                pass

        for y in regex_matches_commit_hash(message.content):
            # trim off the ## leading
            hash = y.group()[2:]
            # print(f'commit {hash}')

            commit = r.get_commit(hash)
            if commit is not None:
                # print('commit', commit)
                if use_embeds:
                    await self.send_commit_embed(commit, message.channel)
                else:
                    await self.send_commit_message(commit, message.channel)


        # if regex matches
        # ##[0-9][0-9][0-9][0-9] $
        # then use API to check if issue
        # or if PR
        # and then link to that

        # if regex matches
        # ##[a-f][0-9] 9-40 characters
        # then check if that's a valid commit (or dont!)
        # and link to that

        # if regex matches
        # ##[a-z]
        # check if that's a valid branch (again, or dont)
        # and link to that

    async def send_commit_message(self, commit: Commit, channel):
        await channel.send(commit.html_url)

    async def send_commit_embed(self, commit: Commit, channel):

        state = commit.get_combined_status().state

        color=discord.Colour.blurple()

        if state == 'failure':
            color=discord.Colour.dark_red()
        elif state == 'pending':
            color=discord.Colour.dark_gold()
        elif state == 'success':
            color=discord.Colour.green()

        description = f'[{state}] {commit.commit.message}'

        commit_embed = discord.Embed(
            title=f'Commit {commit.sha}',
            description=description,
            url=commit.html_url,
            color=color
        )

        await channel.send(content='', embed=commit_embed)

    async def send_issue_message(self, issue: Issue, channel):
        await channel.send(issue.html_url)

    async def send_issue_embed(self, issue: Issue, channel):
        title = f'{issue.repository.full_name} Issue #{issue.number} {issue.title}'

        if issue.body is not None:
            description = (issue.body[:75] + '...') if len(issue.body) > 75 else issue.body
        else:
            description = 'No description provided.'

        issue_embed = discord.Embed(
            title=title,
            description=description,
            url=issue.html_url
        )

        # issue_embed.set_footer(text='Discord Git Linker')

        await channel.send(content='', embed=issue_embed)

    async def send_pullrequest_embed(self, issue: Issue, pr: PullRequest, channel):
        title = f'{issue.repository.full_name} PR #{pr.number} {pr.title}'

        if pr.body is not None:
            description = (pr.body[:75] + '...') if len(pr.body) > 75 else pr.body
        else:
            description = 'No description provided.'

        issue_embed = discord.Embed(
            title=title,
            description=description,
            url=pr.html_url
        )

        # issue_embed.set_footer(text='Discord Git Linker')

        await channel.send(content='', embed=issue_embed)

    async def send_pullrequest_message(self, issue: Issue, pr: PullRequest, channel):
        await channel.send(pr.html_url)

    @commands.command()
    async def authorize(self, ctx, github_token):
        """
        Stores the github access token for a user
        :param github_access_token:
        :return:
        """
        if ctx.guild is not None:
            await ctx.send("Don't use this command in a server, instead send it as DM to the bot. " +
                           "You can reset your token here.")
        else:
            await ctx.send("Ok I'm storing your token associated with your user. If at any point you wish to revoke" +
                           " this access, use the ##revoke command, and invalidate your token here.")
            user_id = ctx.author.id

            cur = self.user_auth_db.cursor()
            to_insert = (user_id, github_token)
            cur.execute('''
                INSERT OR REPLACE INTO UserGithubAuthorization
                (DiscordUserId, GithubAuthorizationToken) 
                VALUES (?, ?);''', to_insert)
            self.user_auth_db.commit()

    @commands.command(aliases=['logout', 'log-out', 'signout', 'sign-out'])
    @commands.bot_has_permissions(send_messages=True)
    async def revoke(self, ctx):
        """
        Revokes a user's github token
         and removes all of the links that have been made by that user
        :param ctx:
        :return:
        """

        c = self.user_auth_db.cursor()
        c.execute('''DELETE FROM UserGithubAuthorization WHERE DiscordUserId = ?;''', (ctx.author.id,))
        # delete all of the channel links
        c.execute(
            '''DELETE FROM LinkChannels WHERE AuthorDiscordUserId = ?;''', (ctx.author.id, ))
        # and the guild links
        c.execute(
            '''DELETE FROM LinkGuilds WHERE AuthorDiscordUserId = ?;''', (ctx.author.id,))

        self.user_auth_db.commit()

        await ctx.send("Ok, I've deleted your token and revoked all of your links." +
                       " You should also revoke your token at <link>")

    def insert_guild(self, guild_id, user_id, repo_url, user_exclusive):
        """
        Removes existing bindings for a guild by this user that match by guild, user and exclusivity
        inserts new bindings for the guild or user
        :param guild_id:
        :param channel_id:
        :param user_id:
        :param repo_url:
        :param user_exclusive:
        :return:
        """
        # print('inserting into guild', guild_id, 'by user', user_id, 'url', repo_url, 'exclusive', user_exclusive)

        c = self.user_auth_db.cursor()

        # remove bindings for the guild matched to exclusivity
        c.execute(
            '''
            DELETE FROM LinkGuilds
            WHERE GuildId = ? AND AuthorDiscordUserId = ? AND AuthorOnly = ?;
            ''', (guild_id, user_id, user_exclusive, )
        )

        timenow = datetime.datetime.now()

        # insert new bindings into this channel
        c.execute(
            '''
            INSERT INTO LinkGuilds
            (GuildId, AuthorDiscordUserId, CreatedAt, RepoName, AuthorOnly)
            VALUES 
            (       ?,         ?,            ?,         ?,        ?);
        ''', (guild_id, user_id, timenow, repo_url, user_exclusive, ))

        self.user_auth_db.commit()

    def insert_channel(self, guild_id, channel_id, user_id, repo_url):
        """
        Removes existing bindings for this channel by this user
        Inserts a new binding for this channel by this user
        :param guild_id:
        :param channel_id:
        :param user_id:
        :param repo_url:
        :return:
        """
        # print('inserting into channel', guild_id, 'by user', user_id, 'url', repo_url, 'channel', channel_id)
        c = self.user_auth_db.cursor()

        # remove existing bindings for this channel
        c.execute(
            '''
            DELETE FROM LinkChannels
            WHERE GuildId = ? AND ChannelId = ?;
            ''', (guild_id, channel_id, )
        )

        timenow = datetime.datetime.now()

        # insert new bindings into this channel
        c.execute(
            '''
            INSERT INTO LinkChannels
            (GuildId, ChannelId, AuthorDiscordUserId, CreatedAt, RepoName)
            VALUES 
            (       ?,         ?,            ?,         ?,        ?);
        ''', (guild_id, channel_id, user_id, timenow, repo_url, ))

        # save changes made to the database
        self.user_auth_db.commit()
        # print('done')

    @commands.guild_only()
    @commands.has_permissions(manage_messsages=True)
    @commands.bot_has_permissions(send_messages=True)
    @commands.command()
    async def unlink_guild(self, ctx):
        """
        Unlinks all of the links made by the author in a guild
        :param ctx:
        :return:
        """
        # only works in guild
        if ctx.guild is None:
            return

    @commands.check(only_dm)
    @commands.command()
    async def unlink_me(self, ctx):
        """
        Unlinks the user's links in the current channel
        :param ctx:
        :return:
        """
        # works in guild and personal channels


    @commands.guild_only()
    @commands.has_permissions(manage_messsages=True)
    @commands.bot_has_permissions(send_messages=True)
    @commands.command()
    async def unlink_channel(self, ctx):
        """
        Unlinks a channel.
        :param ctx:
        :return:
        """

        # todo enforce permissions requirements
        # only manage channel link and unlink channels

        # remove based on channel id match
        # don't care about who does
        guild_id = ctx.guild.id
        channel_id = ctx.channel.id

        c = self.user_auth_db.cursor()

        c.execute(
            '''DELETE FROM LinkChannels 
            WHERE GuildId = ? AND ChannelId = ?;''',
            (guild_id, channel_id, )
        )

        self.user_auth_db.commit()

        c.close()

    @commands.guild_only()
    @commands.has_permissions(manage_messsages=True)
    @commands.bot_has_permissions(send_messages=True)
    @commands.cooldown(5, 60, commands.BucketType.user)
    @commands.command()
    async def link_channel(self, ctx, repo_url):
        """
        Associates a channel with a GitHub repo
        valid syntax for the repo should be https://github.com/Chris-Johnston/CSSBot_Py

        Maybe I should change that to be Chris-Johnston/CSSBot_Py , only the name and repo
        :param ctx:
        :param repo_url:
        :return:
        """

        # if ctx.guild is None:
        #     print('only works in a guild, use link me')
        #     await ctx.send('this only works in guild, use ##link_me instead')
        #     return

        # check to see if the repo url is in the format
        # https://github.com/owner/repo
        # or just owner repo

        repo_name = regex_get_repo_name_from_link(repo_url)
        if repo_name is not None:
            # print(f'using the repo name [{repo_name}]')

            auth = self.get_authorization_for_context(ctx.author.id)

            if auth is None:
                await ctx.send('You need to be logged in to link a channel. See `##login`')
                return

            # login with the access token
            gh = Github(auth)
            try:
                # try to get a repo of the current user
                r = gh.get_repo(repo_name)

                # r = gh.get_repo(repo_name)
                await ctx.send(f'using the repo {r.html_url}')

                # got the repo just fine, actually insert this into the database now

                # insert into the database
                self.insert_channel(ctx.guild.id, ctx.channel.id, ctx.author.id, repo_url)

            except UnknownObjectException as e:
                # the PR / commit / whatever wasn't found
                pass

    @commands.guild_only()
    @commands.has_permissions(manage_messsages=True)
    @commands.bot_has_permissions(send_messages=True)
    @commands.cooldown(5, 60, commands.BucketType.user)
    @commands.command()
    async def link_guild(self, ctx, repo_url):
        repo_name = regex_get_repo_name_from_link(repo_url)
        if repo_name is not None:
            auth = self.get_authorization_for_context(ctx.author.id)
            if auth is None:
                await ctx.send('You need to be logged in to link a channel. See `##login`')
                return

            # login with the access token
            gh = Github(auth)
            try:
                r = gh.get_repo(repo_name)
                await ctx.send(f'Ok! I\'m using the URL: {r.html_url}')
                self.insert_guild(ctx.guild.id, ctx.author.id, repo_url, False)
            except UnknownObjectException:
                # print('unknown object')
                pass
        else:
            # print('parse error')
            pass

    @commands.check(only_dm)
    @commands.cooldown(5, 60, commands.BucketType.user)
    @commands.command()
    async def link_me(self, ctx, repo_url):
        repo_name = regex_get_repo_name_from_link(repo_url)
        if repo_name is not None:
            # print(f'using the repo name [{repo_name}]')

            auth = self.get_authorization_for_context(ctx.author.id)
            if auth is None:
                # print('not logged in')
                await ctx.send('You need to be logged in to link a repo. See `##login`')
                return

            # login with the access token
            gh = Github(auth)
            try:
                r = gh.get_repo(repo_name)
                await ctx.send(f'Ok! I\'m using the URL: {r.html_url}')

                self.insert_guild(ctx.guild.id, ctx.author.id, repo_url, True)
            except UnknownObjectException:
                # print('unknown object')
                pass

    @commands.command()
    async def about(self, ctx):
        await ctx.send('Discord-Git-Linker: https://github.com/Chris-Johnston/Discord-Git-Linker')

    @commands.command()
    async def invite(self, ctx):
        invite_link = f'https://discordapp.com/oauth2/authorize?client_id={ctx.bot.user.id}&scope=bot&permissions=19456'
        await ctx.send(f'Use this link to invite me to a server: {invite_link}')

def setup(bot):
    bot.add_cog(GitMonitor(bot))


def regex_matches_commit_hash(message: str) -> re:
    """
    Runs regex on the supplies message to see if the message contains a valid commit hash
    reference format

    ##b4effb604f0455d214995f700951b0b76aab9556
    ##0a91b18f0fd5392279e3880cc1cc67f8391a0deb
    ##261515f43b2b872f4760f5d9f21c4366d238a762
    ##261515

    >>> for x in regex_matches_commit_hash('##b4effb604f0455d214995f700951b0b76aab9556'): print(x is None)
    False

    >>> for x in regex_matches_commit_hash('##0a91b18f0fd5392279e3880cc1cc67f8391a0deb '): print(x is None)
    False

    >>> for x in regex_matches_commit_hash('message ##261515f43b2b872f4760f5d9f21c4366d238a762 message'): print(x is None)
    False

    >>> for x in regex_matches_commit_hash(' aa aa ##261515 !!!? ##261515aa !!? ##261515b '): print(x is None)
    False
    False
    False

    :param message:
    :return:
    """
    expression = '##[a-zA-Z0-9]{5,40}( |$)'
    e = re.compile(expression)
    result = e.finditer(message)
    return result

def regex_get_repo_name_from_link(message: str) -> re:
    """
    Gets a single repository name from the given github link

    >>> regex_get_repo_name_from_link('Chris-Johnston/Easier68k')
    'Chris-Johnston/Easier68k'

    >>> regex_get_repo_name_from_link('https://github.com/Chris-Johnston/Easier68k')
    'Chris-Johnston/Easier68k'

    >>> regex_get_repo_name_from_link('https://github.com/Chris-Johnston/ChrisBot')
    'Chris-Johnston/ChrisBot'

    >>> regex_get_repo_name_from_link('https://github.com/Chris-Johnston/ChrisBot.git')
    'Chris-Johnston/ChrisBot'


    >>> regex_get_repo_name_from_link('Chris-Johnston/Chris-Johnston.github.io')
    'Chris-Johnston/Chris-Johnston.github.io'

    >>> regex_get_repo_name_from_link('https://github.com/Chris-Johnston')

    :param message:
    :return:
    """

    # trim off leading http://github.com or https://github.com
    message = message.replace('http://github.com/', '')
    message = message.replace('https://github.com/', '')
    # remove the .git at the end
    if message.endswith('.git'):
        message = message[:-4]

    # ensure that it matches the expected regex pattern of
    # user/repo

    expression = '([a-z]|[A-Z]|[0-9]|-|\.)+\/([a-z]|[A-Z]|[0-9]|-|\.)+$'
    e = re.compile(expression)
    results = e.finditer(message)

    for x in results:
        return x.group()
    return None

def regex_matches_pr_or_issue(message: str) -> re:
    """
    Runs regex on the supplied message to see if the message contains
    a PR reference format

    Valid PR reference format is ##\d\d* .
    This should match with

    ##123
    ##1
    Message #1
    #1 Message

    >>> for x in regex_matches_pr_or_issue('##123 '): print(x is None)
    False

    >>> for x in regex_matches_pr_or_issue('#1'): print(x)

    >>> for x in regex_matches_pr_or_issue('message #1'): print(x)

    >>> for x in regex_matches_pr_or_issue(' #1 message'): print(x)

    >>> for x in regex_matches_pr_or_issue('#123'): print(x)

    >>> for x in regex_matches_pr_or_issue('Message##123'): print(x is None)
    False

    >>> for x in regex_matches_pr_or_issue('##ABC'): print(x)

    >>> for x in regex_matches_pr_or_issue('##1A'): print(x)

    >>> for x in regex_matches_pr_or_issue('##123'): print(x is None)
    False

    >>> for x in regex_matches_pr_or_issue('message ##123 Message? ##345 message!?'): print(x is None)
    False
    False

    :param message: the message to check
    :return:
    """
    expression = '##\d\d*( |$)'
    e = re.compile(expression)
    result = e.finditer(message)
    return result

# for testing
if __name__ == '__main__':
    import doctest
    doctest.testmod()
