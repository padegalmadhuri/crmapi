let express = require('express');
let cors = require('cors');
let bcrypt = require('bcrypt');
let bodyParser = require('body-parser');
let mongodb = require('mongodb');
let MongoClient = mongodb.MongoClient;
const ObjectId = mongodb.ObjectID;
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
dotenv.config();
let dbURL = process.env.dbURL;
const app = express();
const nodemailer = require('nodemailer');

let transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD
    }
});

let mailOptions = {
    from: process.env.EMAIL,
    to: '',
    subject: 'Sending Email using Node.js',
    html: `<h1>Hi from node</h1><p> Messsage</p>`
};
const port = process.env.PORT || 3000;
app.use(cors());
app.use(bodyParser.json());
app.listen(port, () => {
    console.log(`Listening in port-${port}`)
});
async function authenticate(req, res, next) {
    if (req.headers.authorization === undefined) {
        res.status(401).json({
            message: 'Token not present'
        })
    } else {
        jwt.verify(req.headers.authorization, 'qwertyuiopasdfghjkl', (err, decode) => {
            if (err) {
                res.status(400).json({
                    message: 'session expired'
                });
            } else {
                console.log(decode);
                req.userType = decode.userType;
                if (req.accessRights === []) {
                    req.accessRights = ["view"]
                }
                req.accessRights = decode.accessRights
                next();
            }
        })
    }
}

function permission(allowedUsers) {
    const isAllowed = type => allowedUsers.indexOf(type) > -1;
    return (req, res, next) => {
        console.log(req.userType, allowedUsers, isAllowed(req.userType))
        if (isAllowed(req.userType)) {
            next();
        } else {
            res.status(401).json({
                message: 'Not authorized to access'
            })
        }
    }
}

function accessVerification(access) {
    const isAllowed = accessRights => accessRights.indexOf(access) > -1;
    return (req, res, next) => {
        if (req.userType === "employee") {
            if (isAllowed(req.accessRights)) {
                next();
            } else {
                res.status(401).json({
                    message: 'Have no access'
                })
            }
        } else {
            next();
        }

    }
}
app.get('/', (req, res) => {
    res.json({
        available_api: [{
            endpoint: "/register",
            method: "post"
        }, {
            endpoint: "/accountverification",
            method: "post"
        }, {
            endpoint: "/forgotpassword",
            method: "post"
        }, {
            endpoint: "/resetpassword",
            method: "post"
        }, {
            endpoint: "/login",
            method: "post"
        }, {
            endpoint: "/adduser",
            method: "post"
        }, {
            endpoint: "/createlead",
            method: "post"
        }, {
            endpoint: "/updatelead",
            method: "put"
        }, {
            endpoint: "/deletelead",
            method: "delete"
        }, {
            endpoint: "/listlead",
            method: "get"
        }, {
            endpoint: "/createcontact",
            method: "post"
        }, {
            endpoint: "/updatecontact",
            method: "put"
        }, {
            endpoint: "/deletecontact",
            method: "delete"
        }, {
            endpoint: "/listcontact",
            method: "get"
        }, ]
    })
});
//resgister endpoint
app.post('/register', async(req, res) => {
    let { email, firstName, lastName, password, userType, accessRights } = req.body;
    if (email === undefined || firstName === undefined || lastName === undefined || password === undefined || userType === undefined || accessRights === undefined) {
        res.status(400).json({
            message: 'Fields missing'
        });
    } else {
        let client = await MongoClient.connect(dbURL).catch((err) => { throw err; });
        let db = client.db('crm');
        let data = await db.collection('users').findOne({ email }).catch((err) => { throw err; });
        if (data) {
            res.status(400).json({
                message: 'Email already registered'
            });
        } else {
            let saltRounds = 10;
            let salt = await bcrypt.genSalt(saltRounds).catch((err) => { throw err; });
            let hash = await bcrypt.hash(password, salt).catch((err) => { throw err; });
            password = hash;
            let accountVerified = false;
            await db.collection('users').insertOne({ email, firstName, lastName, password, userType, accountVerified, accessRights }).catch(err => { throw err; });
            let buf = await require('crypto').randomBytes(32);
            let token = buf.toString('hex');
            await db.collection('users').updateOne({ email }, { $set: { verificationToken: token } });
            client.close();
            mailOptions.to = email;
            mailOptions.subject = 'CRM-Account verification '
            mailOptions.html = `<html><body><h1>Account Verification Link</h1>
                                 <h3>Click the link below to verify the account</h3>
                                <a href='${process.env.urldev}/#/verifyaccount/${token}/${req.body.email}'>${process.env.urldev}/#/verifyaccount/${token}/${req.body.email}</a><br>`;
            transporter.sendMail(mailOptions, function(error, info) {
                if (error) {
                    console.log(error);
                    res.status(500).json({
                        message: "An error occured,Please try again later"
                    })
                } else {
                    console.log('Email sent: ' + info.response);
                    res.status(200).json({
                        message: `Registration Successfull,Verification mail sent to ${email}`,
                    })
                    client.close();
                }
            });


        }
    }
})
app.post('/accountverification', async(req, res) => {
    let { verificationToken, email } = req.body;
    let client = await mongodb.connect(dbURL).catch(err => { throw err });
    let db = client.db('crm');
    let data = await db.collection('users').findOne({ email, verificationToken }).catch(err => { throw err });
    if (data) {
        await db.collection('users').updateOne({ email }, { $set: { verificationToken: '', accountVerified: true } });
        client.close();
        res.status(200).json({
            message: 'Account verification succesfull'
        });
    } else {
        res.status(400).json({
            message: 'Account Verification failes, retry again'
        });
    }
});
app.post('/forgotpassword', async(req, res) => {
    let { email } = req.body;
    let client = await mongodb.connect(dbURL).catch(err => { throw err; });
    let db = client.db('crm');
    let data = await db.collection('users').findOne({ email }).catch(err => { throw err });
    if (data) {
        let buf = await require('crypto').randomBytes(32);
        let token = buf.toString('hex');
        await db.collection('users').updateOne({ email }, { $set: { passwordResetToken: token } });
        client.close();
        mailOptions.to = email;
        mailOptions.subject = 'CRM-Password reset';
        mailOptions.html = `<html><body><h1>Password reset Link</h1>
        <h3>Click the link below to reset password</h3>
       <a href='${process.env.urldev}/#/verifyaccount/${token}/${req.body.email}'>${process.env.urldev}/#/verifyaccount/${token}/${req.body.email}</a><br>`;
        transporter.sendMail(mailOptions, function(error, info) {
            if (error) {
                console.log(error);
                res.status(500).json({
                    message: "An error occured,Please try again later"
                })
            } else {
                console.log('Email sent: ' + info.response);
                res.status(200).json({
                    message: `Verification mail sent to ${req.body.email}`,
                })
                client.close();
            }
        });

    } else {
        res.status(400).json({
            message: 'Email does not exist'
        });
    }
})
app.post('/resetpassword', async(req, res) => {
    let { email, password, passwordResetToken } = req.body;
    let client = await mongodb.connect(dbURL).catch(err => { throw err });
    let db = client.db('crm');
    let data = await db.collection('users').findOne({ email, passwordResetToken }).catch(err => { throw err });
    if (data) {
        let saltRounds = 10;
        let salt = await bcrypt.genSalt(saltRounds).catch((err) => { throw err; });
        let hash = await bcrypt.hash(password, salt).catch((err) => { throw err; });
        password = hash;
        await db.collection('users').updateOne({ email, passwordResetToken }, { $set: { password, passwordResetToken: "" } }).catch(err => { throw err });
        res.status(200).json({
            message: 'Password reset successfull'
        });
    } else {
        res.status(400).json({
            message: 'Password reset failed, Try reseting again'
        });
    }
    client.close();
});
app.post("/login", async(req, res) => {
    let { email, password } = req.body;
    if (email === undefined || password === undefined) {
        res.status(400).json({
            message: 'Fields missing'
        });
    } else {
        let client = await mongodb.connect(dbURL).catch(err => { throw err; });
        let db = client.db('crm');
        let data = await db.collection('users').findOne({ email }).catch(err => { throw err; });
        if (data) {
            if (data.accountVerified) {
                bcrypt.compare(password, data.password, function(err, result) {
                    if (err) throw err;
                    if (result) {
                        jwt.sign({ id: data["_id"], email: data["email"], userType: data["userType"], accessRights: data['accessRights'] }, 'qwertyuiopasdfghjkl', { expiresIn: '10h' }, function(err, token) {
                            if (err) throw err;
                            client.close();
                            res.status(200).json({
                                message: "login successfull",
                                token,
                                email
                            })
                        });
                    } else {
                        client.close();
                        res.status(401).json({
                            message: "password incorrect"
                        })
                    }
                })
            } else {
                res.status(400).json({
                    message: 'verify your account to login'
                });
            }

        } else {
            client.close();
            res.status(400).json({
                message: 'User not found'
            })
        }
    }

});
app.post('/adduser', [authenticate, permission(["admin", "manager"])], async(req, res) => {
    let { email, firstName, lastName, accessRights } = req.body;
    let userType = "employee";
    if (email === undefined || firstName === undefined || lastName === undefined || userType === undefined || accessRights === undefined) {
        res.status(400).json({
            message: 'Fields missing'
        });
    } else {
        let client = await MongoClient.connect(dbURL).catch((err) => { throw err; });
        let db = client.db('crm');
        let data = await db.collection('users').findOne({ email }).catch((err) => { throw err; });
        if (data) {
            res.status(400).json({
                message: 'Email already registered'
            });
        } else {
            let password = await require('crypto').randomBytes(10);
            password = password.toString('hex');
            let saltRounds = 10;
            let salt = await bcrypt.genSalt(saltRounds).catch((err) => { throw err; });
            let hash = await bcrypt.hash(password, salt).catch((err) => { throw err; });
            // password = hash;
            let accountVerified = false;
            await db.collection('users').insertOne({ email, firstName, lastName, password: hash, userType, accountVerified, accessRights }).catch(err => { throw err; });
            let buf = await require('crypto').randomBytes(32);
            let token = buf.toString('hex');
            await db.collection('users').updateOne({ email }, { $set: { verificationToken: token } });
            client.close();
            mailOptions.to = email;
            mailOptions.subject = 'CRM-Account verification '
            mailOptions.html = `<html><body><h1>Account Verification Link</h1>
                                 <h3>Click the link below to verify the account</h3>
                                 <h3>Your password is :${password}
                                <a href='${process.env.urldev}/#/verifyaccount/${token}/${req.body.email}'>${process.env.urldev}/#/verifyaccount/${token}/${req.body.email}</a><br>`;
            transporter.sendMail(mailOptions, function(error, info) {
                if (error) {
                    console.log(error);
                    res.status(500).json({
                        message: "An error occured,Please try again later"
                    })
                } else {
                    console.log('Email sent: ' + info.response);
                    res.status(200).json({
                        message: `User added Successfully,Verification mail sent to ${email}`,
                    })
                    client.close();
                }
            });
        }
    }
})
app.post('/createlead', [authenticate, accessVerification("create")], async(req, res) => {
    let { owner, firstName, phone, lastName, company, email, leadStatus } = req.body;
    if (owner === undefined || firstName === undefined || phone === undefined || email === undefined || leadStatus === undefined) {
        res.status(400).json({
            message: 'Required Fields missing'
        });
    } else {
        let client = await mongodb.connect(dbURL).catch(err => { throw err });
        let db = client.db('crm');
        await db.collection('leads').insertOne(req.body).catch(err => { throw err });
        let managers = await db.collection('users').find({ userType: "manager" }).toArray().catch(err => { throw err; });
        for (let i of managers) {
            mailOptions.to = i.email;
            mailOptions.subject = 'Lead added';
            mailOptions.html = `<html><body><h1>New lead added</h1>
            <h3>Details of new lead</h3>
            <h5>Lead Owner : ${owner}</h5>
            <h5>First Name : ${firstName}</h5>
            <h5>Email : ${email}</h5>
            <h5>Phone Number : ${phone}</h5>
            <h5>Lead Status : ${leadStatus}</h5>`;
            transporter.sendMail(mailOptions, function(error, info) {
                if (error) {
                    console.log(error);
                } else {
                    console.log('Email sent: ' + info.response);
                }
            });
        }
        let admins = await db.collection('users').find({ userType: "admin" }).toArray().catch(err => { throw err; });
        for (let i of admins) {
            mailOptions.to = i.email;
            mailOptions.subject = 'Lead added';
            mailOptions.html = `<html><body><h1>New lead added</h1>
            <h3>Details of new lead</h3>
            <h5>Lead Owner : ${owner}</h5>
            <h5>First Name : ${firstName}</h5>
            <h5>Email : ${email}</h5>
            <h5>Phone Number : ${phone}</h5>
            <h5>Lead Status : ${leadStatus}</h5>`;
            transporter.sendMail(mailOptions, function(error, info) {
                if (error) {
                    console.log(error);
                } else {
                    console.log('Email sent: ' + info.response);
                }
            });
        }
        client.close();
        res.status(200).json({
            message: 'Lead created'
        });
    }
});
app.put('/updatelead', [authenticate, accessVerification("update")], async(req, res) => {
    let { leadId } = req.body;
    if (leadId === undefined) {
        res.status(400).json({
            message: 'Required Fields missing'
        });
    } else {
        let client = await mongodb.connect(dbURL).catch(err => { throw err });
        let db = client.db('crm');
        leadId = new ObjectId(leadId);
        delete req.body.leadId;
        await db.collection('leads').updateOne({ "_id": leadId }, { $set: req.body }).catch(err => { throw err });
        client.close();
        res.status(200).json({
            message: 'Lead updated'
        });
    }
});
app.delete('/deletelead', [authenticate, accessVerification("delete")], async(req, res) => {
    let { leadId } = req.body;
    if (leadId === undefined) {
        res.status(400).json({
            message: 'Required Fields missing'
        });
    } else {
        let client = await mongodb.connect(dbURL).catch(err => { throw err });
        let db = client.db('crm');
        leadId = new ObjectId(leadId);
        delete req.body.leadId;
        await db.collection('leads').deleteOne({ "_id": leadId }).catch(err => { throw err });
        client.close();
        res.status(200).json({
            message: 'Lead deleted'
        });
    }
});
app.get('/listlead', [authenticate, accessVerification("view")], async(req, res) => {
    let client = await mongodb.connect(dbURL).catch(err => { throw err });
    let db = client.db('crm');
    let leads = await db.collection("leads").find().toArray().catch(err => { throw err; });
    client.close();
    res.status(200).json({
        leads
    });
});
app.post('/createcontact', [authenticate, accessVerification("create")], async(req, res) => {
    let { owner, firstName, phone, lastName, company, email, dob } = req.body;
    if (owner === undefined || firstName === undefined || phone === undefined || email === undefined) {
        res.status(400).json({
            message: 'Required Fields missing'
        });
    } else {
        let client = await mongodb.connect(dbURL).catch(err => { throw err });
        let db = client.db('crm');
        await db.collection('contacts').insertOne(req.body).catch(err => { throw err });
        client.close();
        res.status(200).json({
            message: 'contact created'
        });
    }
});
app.put('/updatecontact', [authenticate, accessVerification("update")], async(req, res) => {
    let { contactId } = req.body;
    if (contactId === undefined) {
        res.status(400).json({
            message: 'Required Fields missing'
        });
    } else {
        let client = await mongodb.connect(dbURL).catch(err => { throw err });
        let db = client.db('crm');
        contactId = new ObjectId(contactId);
        delete req.body.contactId;
        await db.collection('contacts').updateOne({ "_id": contactId }, { $set: req.body }).catch(err => { throw err });
        client.close();
        res.status(200).json({
            message: 'Contact updated'
        });
    }
});
app.delete('/deletecontact', [authenticate, accessVerification("delete")], async(req, res) => {
    let { contactId } = req.body;
    if (contactId === undefined) {
        res.status(400).json({
            message: 'Required Fields missing'
        });
    } else {
        let client = await mongodb.connect(dbURL).catch(err => { throw err });
        let db = client.db('crm');
        contactId = new ObjectId(contactId);
        delete req.body.contactId;
        await db.collection('contacts').deleteOne({ "_id": contactId }).catch(err => { throw err });
        client.close();
        res.status(200).json({
            message: 'Contact deleted'
        });
    }
});
app.get('/listcontacts', [authenticate, accessVerification("view")], async(req, res) => {
    let client = await mongodb.connect(dbURL).catch(err => { throw err });
    let db = client.db('crm');
    let contacts = await db.collection("contacts").find({}).toArray().catch(err => { throw err; });
    client.close();
    res.status(200).json({
        contacts
    });
});