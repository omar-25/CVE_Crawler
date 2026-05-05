class CVE:
    def __init__(self, cve_id, title, description, published_date, 
                 last_modified_date, cwe, cvss, vendor, product, affected_versions, attackType=None):
        self.cve_id              = cve_id
        self.title               = title
        self.description         = description
        self.published_date      = published_date
        self.last_modified_date  = last_modified_date
        self.cwe                 = [c.text.strip() for c in cwe] if cwe else []
        self.cvss                = cvss        
        self.vendor              = vendor
        self.product             = product
        self.affected_versions   = affected_versions if affected_versions else []
        self.attackType          = attackType

    def __str__(self):
        return (
            f"CVE ID       : {self.cve_id}\n"
            f"Title        : {self.title}\n"
            f"Description  : {self.description}\n"
            f"Published    : {self.published_date}\n"
            f"Modified     : {self.last_modified_date}\n"
            f"CWE          : {self.cwe}\n"
            f"CVSS         : {self.cvss}\n"
            f"Vendor       : {self.vendor}\n"
            f"Product      : {self.product}\n"
            f"Affected     : {self.affected_versions}\n"
            f"Attack Type  : {self.attackType}\n"
        )

    def to_dict(self):
        return {
            "cve_id"            : self.cve_id,
            "title"             : self.title,
            "description"       : self.description,
            "published_date"    : self.published_date,
            "last_modified_date": self.last_modified_date,
            "cwe"               : self.cwe,
            "cvss"              : self.cvss,
            "vendor"            : self.vendor,
            "product"           : self.product,
            "affected_versions" : self.affected_versions,
            "attackType"        : self.attackType
        }