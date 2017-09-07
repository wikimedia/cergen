import logging
import os
import subprocess


def run_command(command, creates=None):
    """
    Executes a command in a subshell and logs the output.

    Args:
        command (list of str): a list of command args to pass to subprocess.check_output

    Returns:
        bool: True if the command exited with 0, else False
    """
    logger = logging.getLogger(__name__)

    if isinstance(command, str):
        command = command.split()
    try:
        command_string = ' '.join(command)

        logger.debug('Running command: %s', command_string)
        output = subprocess.check_output(command, stderr=subprocess.STDOUT)
        for ln in output.splitlines():
            logger.debug(ln)

        # Ensure that any files that this command should have created exist.
        if creates is not None:
            if isinstance(creates, str):
                creates = [creates]
            for f in creates:
                if not os.path.exists(f):
                    logger.error(
                        'command succeeded, but was expected to create file %s '
                        'and it does not exist. command: %s', f, command_string
                    )
                    return False

    except subprocess.CalledProcessError as e:
        for ln in e.output.splitlines():
            logger.error(ln)
        logger.error('command returned status %d: %s', e.returncode, command_string)
        return False

    logger.debug('command succeeded: %s', command_string)
    return True
