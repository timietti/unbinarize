import nska_deserialize as nd
from time import localtime, strftime
import os
import sys
import getopt
import subprocess
from getpass import getuser
import magic
import shutil
import plistlib
import sqlite3
import re

#### Constants

RIGHT_NOW=strftime('%Y%m%d-%H%M%S', localtime())
access_rights = 0o755

usage = '\r\nunbinarize.py by Timo Miettinen 2020 \r\n'\
        'This script converts binary data from Apple devices to human readable\r\n'\
        'format and copies every piece of evidence to one folder.\r\n\r\n'\
        'Usage: python unbinarize.py -h | [-f <path_to_ftree_binary>] -i <input_dir> -o <output_dir>\r\n'\
        'Example: unbinarize.py -i ~/Documents/backup -o ~/Documents/output \r\n\r\n'

usage_short = '\r\nUsage: python unbinarize.py -h | [-f <path_to_ftree_binary>] -i <input_dir> -o <output_dir>\r\n'

#### Global variables

input_dir = ''
output_dir = ''
#ftree = False
n_nskeyed = 0
n_text = 0
n_bin = 0
n_xml = 0
n_sql = 0

#### Functions

def deserialize_file(path):
    global n_nskeyed
    with open(path, 'rb') as f:
        try:
            deserialized_plist = nd.deserialize_plist(f)
#            print(deserialized_plist)
        except (nd.DeserializeError, nd.biplist.NotBinaryPlistException, nd.biplist.InvalidPlistException, nd.ccl_bplist.BplistError, ValueError, TypeError, OSError, OverflowError) as ex:
                # These are all possible errors from libraries imported
#            print('Had exception: ' + str(ex))
            deserialized_plist = None

    if deserialized_plist:
#        output_path_plist = outputdir + '_deserialized.plist'
#        output_path_json  = outputdir + '_deserialized.json'

#        nd.write_plist_to_json_file(deserialized_plist, output_path_json)
        nd.write_plist_to_file(deserialized_plist, path)
#        with open(path, "wb") as out_plist:
#            plistlib.dump(deserialized_plist, out_plist, fmt=plistlib.FMT_BINARY)
#        print ("%s" % path)
        n_nskeyed = n_nskeyed + 1

def find_files(path):
    result = []
    for root, dirs, files in os.walk(path):
        for f in files:
            result.append(os.path.join(root, f))
    return result

def delete_links(path):
    try:
        for root, dirs, files in os.walk(path):
            for f in files:
                filepath = os.path.join(root, f)
                if os.path.islink(filepath):
                    os.unlink(filepath)
        print ("OK\r\n")
    except OSError:
        print ("Deletion of the links failed.\r\n")

def create_dir(path):
    if not os.path.exists(path):
        try:
            os.mkdir(path, access_rights)
        except OSError:
            print ("Creation of the directory %s failed.\r\n" % path)
        else:
            print ("Successfully created the directory %s.\r\n" % path)
    else:
        print ("Directory %s already exists.\r\n" %path)

def set_file_permissions(path, permissions):
    try:
        for root, dirs, files in os.walk(path):
            for d in dirs:
                os.chmod(os.path.join(root, d), permissions,
                         follow_symlinks=False)
            for f in files:
                os.chmod(os.path.join(root, f), permissions,
                         follow_symlinks=False)
        print ("OK\r\n")
    except OSError:
        print ("User %s does not have permission to all files. Please give sudo password.\r\n" % getuser())
        command = subprocess.Popen(['sudo', '/bin/chmod', '-R',
                                    str(oct(permissions)[2:]), path]).communicate()

def path_to_filename(path):
    return path[len(input_dir):].replace('/', '|')

def dump_file(path, outputfilename, magic_name):
    global n_bin
    global n_xml
    global n_sql
    global n_text
    n_subplist = 1
    if "Apple binary property list" in magic_name:
        with open(path, 'rb') as in_plist:
            obj_plist = plistlib.load(in_plist)
            with open(output_dir + outputfilename, "w") as out_plist:
                out_plist.write(str(obj_plist))
            for line in obj_plist:
                if isinstance(line, dict):
                    for keys in line:
                        if str(line[keys])[2:8] == 'bplist':
                            with open(output_dir + outputfilename + '|' + keys + '_' + str(n_subplist) + '.plist', "wb") as out_plist:
                                out_plist.write(line[keys])
                            n_subplist = n_subplist +1
                        if isinstance(line[keys], dict):
                            for keyss in line[keys]:
                                if str(line[keys][keyss])[2:8] == 'bplist':
                                    with open(output_dir + outputfilename + '|' + keyss + '_' + str(n_subplist) + '.plist', "wb") as out_plist:
                                        out_plist.write(line[keys][keyss])
                                    n_subplist = n_subplist +1
        n_bin = n_bin + 1
    elif "XML 1.0 document" in magic_name:
        with open(path, 'rb') as in_plist:
            obj_plist = plistlib.load(in_plist, fmt=plistlib.FMT_XML)
            with open(output_dir + outputfilename, "w") as out_plist:
                out_plist.write(str(obj_plist))
            for line in obj_plist:
                if isinstance(line, dict):
                    for keys in line:
                        if str(line[keys])[2:8] == 'bplist':
                            with open(output_dir + outputfilename + '|' + keys + '_' + str(n_subplist) + '.plist', "wb") as out_plist:
                                out_plist.write(line[keys])
                            n_subplist = n_subplist +1
                        if isinstance(line[keys], dict):
                            for keyss in line[keys]:
                                if str(line[keys][keyss])[2:8] == 'bplist':
                                    with open(output_dir + outputfilename + '|' + keyss + '_' + str(n_subplist) + '.plist', "wb") as out_plist:
                                        out_plist.write(line[keys][keyss])
                                    n_subplist = n_subplist +1
        n_xml = n_xml + 1
    elif "SQLite 3.x database" in magic_name:
        con = sqlite3.connect(path)
        with open(output_dir + outputfilename, 'w') as f:
            for line in con.iterdump():
                f.write('%s\n' % line)
                if 'X\'62706C697374' in line:
                    match = re.search('INSERT\sINTO\s\"(\w*)\".*X\'([A-F0-9]*)\'', line)
                    with open(output_dir + outputfilename + '|' + match.group(1) + '_' + str(n_subplist) + '.plist', "wb") as out_plist:
                        out_plist.write(bytes.fromhex(match.group(2)))
                    n_subplist = n_subplist +1
        n_sql = n_sql + 1
    elif "text" in magic_name:
        shutil.copyfile(path, output_dir + outputfilename)
        n_text = n_text + 1


#### Main

def main(argv):

    global input_dir
    global output_dir
    global n_nskeyed
    global n_bin
    global n_xml
    global n_sql
    global n_text

    if len(argv)<1:
        print (usage_short)
        sys.exit()

    try:
#        opts, args = getopt.getopt(argv,"hf:i:o:",["input=","output="])
        opts, args = getopt.getopt(argv,"hi:o:",["input=","output="])
    except getopt.GetoptError:
        print (usage_short)
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print (usage)
            sys.exit()
#        elif opt == '-f':
#            ftree = True
#            ftree_path = arg
        elif opt in ("-i", "--input"):
            input_dir = arg
        elif opt in ("-o", "--output"):
            output_dir = arg
#    print 'Input directory is: ', input_dir
#    print 'Output directory is: ', output_dir

    # Modify dir names to contain absolute path + '/' at the end
    input_dir = os.path.abspath(input_dir) + '/'
    output_dir = os.path.abspath(output_dir) + '/'

    # Create the output directory
    print ("[*] Creating output directory...")
    create_dir(output_dir)

    # Set file permissions for files in input directory
    print ("[*] Setting input directory file permissions to %s..." % str(oct(access_rights)[2:]))
    set_file_permissions(input_dir, access_rights)

    # Remove all symlinks from the inputdir
    print ("[*] Deleting symbolic links from the input directory...")
    delete_links(input_dir)

    # Convert NSKeyedArchive plist files to normal plists and copy to output
    # folder.
    print ("[*] Converting NSKeyedArchive plist files in input directory to normal binary plist...")
    n_nskeyed = 0
    for root, dirs, files in os.walk(input_dir):
        for f in files:
            if magic.from_file(os.path.join(root, f)) == "Apple binary property list":
                deserialize_file(os.path.join(root, f))
    print ("%i files converted.\r\n" % n_nskeyed)

    # Dumping all relevant files to output dir
    print ("[*] Dumping files to output directory...")
    n_text = 0
    n_bin = 0
    n_xml = 0
    n_sql = 0
    for root, dirs, files in os.walk(input_dir):
        for f in files:
            dump_file(os.path.join(root, f), path_to_filename(os.path.join(root, f)), magic.from_file(os.path.join(root, f)))
#            print (magic.from_file(os.path.join(root, f)))
    print ("%i binary plist files copied to output directory." % n_bin)
    print ("%i xml plist files copied to output directory." % n_xml)
    print ("%i SQLite databases copied to output directory." % n_sql)
    print ("%i text files copied to output directory.\r\n" % n_text)

    # Convert NSKeyedArchive plist files to normal plists in output folder.
    print ("[*] Converting NSKeyedArchive plist files in output directory to normal binary plist...")
    n_nskeyed = 0
    for root, dirs, files in os.walk(output_dir):
        for f in files:
            if magic.from_file(os.path.join(root, f)) == "Apple binary property list":
                deserialize_file(os.path.join(root, f))
    print ("%i files converted.\r\n" % n_nskeyed)

    # Convert binary plist files to text files
    print ("[*] Converting binary plist files in output directory to human readable format...")
    n_bin = 0
    for root, dirs, files in os.walk(output_dir):
        for f in files:
            if "Apple binary property list" in magic.from_file(os.path.join(root, f)):
                dump_file(os.path.join(root, f), f, magic.from_file(os.path.join(root, f)))
#            print (magic.from_file(os.path.join(root, f)))
    print ("%i binary plist files converted." % n_bin)

if __name__ == "__main__":
    main(sys.argv[1:])
