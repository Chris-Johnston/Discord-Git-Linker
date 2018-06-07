import discord
from discord.ext import commands
import re

class GitMonitor:

    def __init__(self, bot):
        self.bot = bot

    async def on_command_error(self, ctx, error):
        # print('on command error')
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
        if message.author.user.id == self.bot.user.id:
            return

        #debug
        print(message.content)

        for x in regex_matches_pr_or_issue(message.content):
            print(f'PR/Issue {x.group()}')

        for y in regex_matches_commit_hash(message.content):
            print(f'commit {x.group()}')

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

    @commands.command()
    async def authorize(self, ctx, github_token):
        """

        :param github_access_token:
        :return:
        """
        if ctx.guild is not None:
            await ctx.send("Don't use this command in a server, instead send it as DM to the bot. You can reset your token here.")
        else:
            await ctx.send("Ok I'm storing your token associated with your user. If at any point you wish to revoke this access, use the ##revoke command, and invalidate your token here.")
            user_id = ctx.author.id



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
