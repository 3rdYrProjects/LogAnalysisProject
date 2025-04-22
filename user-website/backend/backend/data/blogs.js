const blogs = [
  {
    id: 1,
    title: "Understanding SQL Injection",
    description:
      "An introduction to SQL injection techniques and prevention methods.",
    image:
      "https://cybersapiens.com.au/wp-content/uploads/2024/06/list-of-100-plus-best-cyber-security-blogs-in-the-world-1024x536.jpg",
    details:
      "SQL injection is a type of security vulnerability where an attacker can execute arbitrary SQL code on the database by injecting malicious input.",
  },
  {
    id: 2,
    title: "Cross-Site Scripting (XSS) Guide",
    description:
      "Learn how XSS attacks work and how to secure your applications.",
    image:
      "https://erepublic.brightspotcdn.com/dims4/default/bcd15e7/2147483647/strip/true/crop/940x490+0+68/resize/840x438!/quality/90/?url=http%3A%2F%2Ferepublic-brightspot.s3.us-west-2.amazonaws.com%2Fc7%2Fe6%2F15cc0c2a576e7e7b79495dba3677%2Fshutterstock-281522084.jpg",
    details:
      "XSS allows attackers to inject malicious scripts into webpages viewed by other users. This guide explains how to protect against such attacks.",
  },
  {
    id: 3,
    title: "Top 10 OWASP Vulnerabilities",
    description:
      "A detailed guide on OWASP's top vulnerabilities for web applications.",
    image:
      "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSU1awa_S5x958hmS1sST4ZubzyaRNIi9Tksg&s",
    details:
      "OWASP Top 10 is a standard awareness document for developers and security professionals. Learn how to mitigate these vulnerabilities.",
  },
  {
    id: 4,
    title: "Phishing Attacks: How to Spot and Avoid Them",
    description:
      "Learn how to identify phishing attempts and protect yourself from scams.",
    image:
      "https://blog.ipleaders.in/wp-content/uploads/2020/08/170509-did-you-fall-for-the-Google-phishing-scam.jpg",
    details:
      "Phishing is a common cyber attack where attackers trick users into revealing sensitive information. This blog explains how to stay safe.",
  },
  {
    id: 5,
    title: "Introduction to Penetration Testing",
    description:
      "A beginner's guide to penetration testing and its importance in cybersecurity.",
    image: "https://insecsys.com/images/penetration-testing.png",
    details:
      "Penetration testing involves simulating cyber attacks to identify vulnerabilities in a system. Learn how it works and why it's essential.",
  },
  {
    id: 6,
    title: "Ransomware: Prevention and Recovery",
    description:
      "Understand ransomware attacks and how to prevent or recover from them.",
    image:
      "https://media.licdn.com/dms/image/v2/D4D10AQE8qBYiZA3Czw/image-shrink_800/image-shrink_800/0/1732661116132?e=2147483647&v=beta&t=dVhVQGMEXwfaK-uvIAPiUGXQcF_rr27SgiehdvOoQaQ",
    details:
      "Ransomware is a type of malware that encrypts files and demands payment for their release. This blog covers prevention and recovery strategies.",
  },
  {
    id: 7,
    title: "Securing IoT Devices",
    description:
      "Learn how to secure Internet of Things (IoT) devices from cyber threats.",
    image: "https://cdn.invicti.com/statics/img/blogposts/iot-security.png",
    details:
      "IoT devices are increasingly targeted by hackers. This blog provides tips on securing your IoT devices.",
  },
  {
    id: 8,
    title: "Zero Trust Security Model",
    description:
      "An overview of the Zero Trust security model and its implementation.",
    image:
      "https://media.licdn.com/dms/image/v2/D5612AQGPDPyH9Hk-1g/article-cover_image-shrink_600_2000/article-cover_image-shrink_600_2000/0/1721914033755?e=2147483647&v=beta&t=FakY3sjdSr1cMdrvZb4TjoK3dlis0VgUIUQnezA9gko",
    details:
      "Zero Trust is a security framework that assumes no user or device is trusted by default. Learn how to implement it in your organization.",
  },
  {
    id: 9,
    title: "Data Encryption Best Practices",
    description:
      "A guide to encrypting data to protect it from unauthorized access.",
    image:
      "https://cdn.prod.website-files.com/664e6b29f3ed49c2317db2f2/665e2e968ee27aa9fde3adc1_647674eab869affb3582b92c_asymmetric%2520encryption.webp",
    details:
      "Data encryption is a critical component of cybersecurity. This blog covers best practices for encrypting sensitive data.",
  },
  {
    id: 10,
    title: "Social Engineering Attacks",
    description:
      "Learn about social engineering techniques and how to defend against them.",
    image:
      "https://www.dragonspears.com/hubfs/images/blog/avoid-these-four-social-engineering-attacks-in-your-organization-1260x630px.png",
    details:
      "Social engineering exploits human psychology to gain access to systems or data. This blog explains common techniques and how to protect yourself.",
  },
]
module.exports = blogs
