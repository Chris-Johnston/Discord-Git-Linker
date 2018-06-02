import discord
import discord.ext import commands

class GitMonitor:

    def __init__(self, bot):
        self.bot = bot

    async def on_message(self, message):
        """
        Listens for when the user has used the

        ##PR ##Issue ##hash ##branch

        syntax in their message, and call the appropriate
        methods when they do

        :param message:
        :return:
        """

        #debug
        print(message.content)

        # if regex matches
        # ##[0-9][0-9][0-9][0-9] ^
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

    @bot.command()
    async def authorize(self, gh_login_username):
        """
        Authorizes this application to have access
        to the private repos on a user's github account.

        First, the user provides their GitHub username with the
        command

        ##authorize Chris-Johnston

        Then, the bot replies with the authorization URL,
        with all of the parameters filled in for the user:

        < github.com/login/oauth/authorize ... >

        When this last authorization step is completed, then the
        user will have the ability to access the PR numbers,
        issues, commits, and branches.

        Hrm... now that I think about it.

        _Anyone_ could just say that they are

        ##authorize Chris-Johnston

        and if Chris-Johnston has already authorized
        a token for the oauth, but not linked their discord
        id with their discord

        authorizations could be done a repo by repo basis?
        so, when registering that a repo should be associated with a
        channel or a guild, we store the repo in a table
        along with whatever id was used

        we would _have_ to use the code feature that is provided by
        github, I think.

        so that way, each server gets their own authorization URL
        and then we can have that go to the authorization server
        and .. I still don't think that would work

        one option would be to consider using the webhook api, I
        think that registering the app on a user basis isn't
        the right thing to do... it should be opt in for the app?

        of course, the easiest option would be to only make it work with
        my own repos and put the authorization token in the config

        or using unauthenticated api, but 60 requests an hour
        is harsh

        you __could__ DM the bot an authorization token. that would
        solve all of my problems. I wouldn't even need to spin up
        a authorization server

        so then the user would (in a DM!, if this is detected in a server
        then attempt to delete the token, ping the user and tell them
        that they need to revoke it)

        ##setup token

        then, in a server

        ##guild github.com/Chris-Johnston/myrepo

        ##channel github.com/Chris-Johnston/myrepo

        this would allow all members of this guild or repo access
        to the repo using the credentials that the user that
        set it up has

        the user can only set up the document if they are registered
        and if they are the owner of a private repo

        so that when any user does something in a channel or guild
        we look up the repo for that guild or channel
        and also look up the user who registered for that guild
        or channel

        then, get the authorization token for that user
        and do whatever requests that they asked for


        #OK I THINK I GOT IT.. never mind

        I can set a parameter in the callback url

        so, when the user wants to go register, first
        they send in a dm the register command
        the bot replies with teh registration url
        where the callback url is the usual
        with the parameter

        ?user_id=<discord user id>

        then, they do that, and the endpoint logs their userid
        and associates the token with them

        if a bad actor were to modify this user id, the end result would
        be that some other user id that isn't the user who logged
        in would have access instead

        I could fix this at a low level by hashing or doing a
        checksum

        I could warn the user that they should not expose this url
        otherwise they could risk a phishing attack

        also this means that anyone could just overwrite other people's
        authorizations, since it's all there

        I would need some way to authenticate this then

        checksum is lazy

        I could sign the user id and username, pass the encrypted
        one as the parameter

        decrypt the result and then use that.. would need
        some way to validate that the values are correct..
        I could use AES, which has error checking.

        https://github.com/ricmoo/pyaes#aes-block-cipher

        well.. even if I do stuff to make it hard to simply replace
        a user id, anyone could just send links around
        which means then that copies the authorization

        so really, that wouldn't solve anything

        honestly I think that sending the token directly is the
        only way to go. Only other option that I can see would be
        to set up a _discord_ authorization as well a github
        authorization, then integrate the two. That just sounds awful.

        :param gh_login_username:
        :return:
        """
        pass

def setup(bot):
    bot.add_cog(GitMonitor(bot))