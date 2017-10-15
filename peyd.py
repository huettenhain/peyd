import sys, re, pefile 

class PEiDSignature:

    def __parse_sig_item(self, signature_item):
        if signature_item == '??':
            return b'.'
        try:
            return re.escape(bytes.fromhex(signature_item))
        except:
            pattern_match = re.match(r'([A-F0-9])\?', signature_item)
            if pattern_match:
                b = pattern_match.group(1)
                return b'['+bytes.fromhex(b+'0')+b'-'+bytes.fromhex(b+'F')+b']'
            pattern_match = re.match(r'\?([A-F0-9])', signature_item)
            if pattern_match:
                x = pattern_match.group(1)
                return b'[' + re.escape(bytes.fromhex(''.join(b + x for b in "0123456789ABCDEF"))) + b']'
            pattern_match = re.match('V(\d)', signature_item)
            if pattern_match:
                return b'(?P<v'+pattern_match.group(1).encode()+b'>.)'
            return b'.'

    def __len__(self):
        return len(self.sequence)

    def __str__(self):
        return '[%s]\nsignature = %s\nep_only = %s\n' % \
            (self.name, ' '.join(self.sequence),
             'true' if self.ep_only else 'false')

    def __repr__(self):
        r = 'E:' if self.ep_only else '?:'
        r += '-'.join(self.sequence)
        return r

    def __init__(self, name, sequence, ep_only):
        self.name = name
        self.sequence = tuple(sequence.strip().split())
        self.pattern = None
        self.ep_only = (ep_only == 'true')

    def __hash__(self):
        return hash(repr(self))

    def __pattern_init(self):
        if self.pattern is None:
            self.pattern = re.compile(b''.join(
                self.__parse_sig_item(x) for x in self.sequence))

    def match_stream(self, bytes):
        self.__pattern_init()
        if self.ep_only:
            return False
        else:
            return self.pattern.search(bytes)

    def match(self, pe_object):
        self.__pattern_init()
        entrypoint = pe_object.OPTIONAL_HEADER.AddressOfEntryPoint
        if self.ep_only:
            for section in pe.sections:
                if section.contains_rva(entrypoint):
                    bytes = section.get_data(entrypoint, len(self))
                    return self.pattern.match(bytes)
        else:
            bytes = pe_object.get_data(0)
            return self.pattern.search(bytes)


class PEiDDataBase:

    def __init__(self):
        self.regular_expression = re.compile(
            r'\[(.*?)\]\s*\nsignature\s*=\s*((?:[A-FJV?0-9]{2}\s*)*).*\nep_only\s*=\s*(true|false)')
        self.signatures = []
        self.signature_names = {}

    def readfile(self, filename):
        signature_matches = self.regular_expression.findall(
            open(filename).read())
        for m in signature_matches:
            sig = PEiDSignature(*m)
            h = hash(sig)
            if h in self.signature_names:
                if sig.name not in self.signature_names[h]:
                    self.signature_names[h].append(sig.name)
            else:
                self.signature_names[h] = [sig.name]
                self.signatures.append(sig)

    def __names(self, sig):
        return self.signature_names[hash(sig)]

    def export(self, filename, interactive=False):
        file_handle = open(filename, 'w')
        if interactive:
            # This is for me only, basically, to create the PEiD.txt signature
            # file. Therefore, it is platform-dependent.
            import msvcrt 
            max_length = 1 + max( len(n) \
                for s in self.signatures \
                for n in self.__names(s) )
        for sig in self.signatures:
            names = self.__names(sig)
            if interactive:
                if len(names) > 1:
                    sys.stdout.write('[PEyD] duplicates found:\n')
                    for name in names:
                        sys.stdout.write('  ')
                        sys.stdout.write(name) 
                        sys.stdout.write('\n')
                    sys.stdout.write('[PEyD] press d to delete a name and a to delete nothing:\n')
                    for name in names:
                        sys.stdout.write('  ')
                        sys.stdout.write(name.ljust(max_length))
                        sys.stdout.flush()
                        if interactive: key = msvcrt.getch() 
                        else: key = b'a'

                        if key != b'd':        
                            sys.stdout.write('[stored]\n')
                            sig.name = name 
                            file_handle.write('%s\n' % sig)
                            if key == b'a': interactive = False
                        else:
                            sys.stdout.write('[remove]\n')
                else:
                    file_handle.write('%s\n' % sig)
            else: 
                for name in names:
                    sig.name = name
                    file_handle.write('%s\n' % sig)

    def all_matches(self, pe_object):
        results = {}
        for s in self.signatures:
            signature_match = s.match(pe_object)
            if signature_match:
                substitutions = signature_match.groupdict()
                for result in self.signature_names[hash(s)]:
                    for key in substitutions:
                        result = result.replace(
                            '%%%s' % key, ord(substitutions[key]))
                    if result not in results: results[result] = 0
                    results[result] += 1
        return results


if __name__ == '__main__':
    from sys import argv
    from glob import glob
    import os.path as op

    id = PEiDDataBase()
    db = op.join( op.split(op.abspath(argv[0]))[0], 'peyd.txt' )
    id.readfile( db )

    for fg in argv[1:]:
      for f in glob(fg):    
        file_name = op.split(f)[-1]
        pe = pefile.PE(f)
        print(file_name)
        matches = id.all_matches(pe)
        for m in matches: 
          print("  %2d x %s" % (matches[m],m) )