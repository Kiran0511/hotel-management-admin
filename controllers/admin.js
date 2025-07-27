exports.getHome = (req, res, next) => {
    if (req.session.admin !== undefined ) {
      return res.render('admin/home', { admin: req.session.admin });
    } else {
      return res.render('admin/home',{ admin: "" });
    }
  };
exports.getLogin = (req, res, next) => {
    if (req.session.admin !== undefined ) {
      return res.render('admin/login', { admin: req.session.admin });
    } else {
      return res.render('admin/login',{ admin: "" });
    }
  };
exports.getRegister = (req, res, next) => {
    if (req.session.admin !== undefined ) {
      return res.render('admin/register', { admin: req.session.admin });
    } else {
      return res.render('admin/register',{ admin: "" });
    }
  };
exports.postRegister = async (req,res,next) =>{
    const connection = require('../db-config')
    const validator = require('validator');
    const bcrypt = require('bcrypt');
    const { email, password } = req.body;
    
    if (!email || !password) {
      req.flash('error', 'All fields are required*');
      req.flash('email', email);
      return res.redirect('/register');
    }
  
    if (!validator.isEmail(email)) {
      req.flash('error', 'Invalid Email');
      req.flash('email', email);
      return res.redirect('/register');
    }
    
    if (!validator.isStrongPassword(password)) {
      req.flash('error', 'Password is weak Try a strong password');
      req.flash('email', email);
      return res.redirect('/register');
    }
  
    // Check if email already exists in the database
    connection.query('SELECT COUNT(*) AS count FROM users WHERE email = ?', [email], (err, results) => {
      if (err) throw err;
      if (results[0].count > 0) {
        req.flash('error', 'Email already exists. Please try again with a different email address.');
        req.flash('email', email);
        return res.redirect('/register');
      } else {
        const saltRounds = 10;
        bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
          if (err) throw err;
          connection.query('INSERT INTO admin (email, password) VALUES (?, ?)', [email, hashedPassword ], (err, result) => {
            if (err) throw err;
            const admin = {
              id: result.insertId,
              email,
            };
            return res.redirect('/login');
          });
        });
      }
    });
  }
  exports.postLogin = (req, res, next) => {
    const connection = require('../db-config');
    const passport = require('passport');
    const bcrypt = require('bcrypt');
    const { email, password } = req.body;
  
    passport.authenticate('local', { usernameField: 'email' }, (err, admin, info) => {
      if (err) {
        req.flash('error', info.message);
        return next(err);
      }
      if (!admin) {
        req.flash('error', info.message);
        return res.redirect('/login');
      }
      // Compare the password entered with the hashed password in the database
      bcrypt.compare(password, admin.password, (err, result) => {
        if (err) {
          req.flash('error', 'Error in bcrypt compare');
          return next(err);
        }
        if (!result) {
          req.flash('error', 'Invalid email or password');
          return res.redirect('/login');
        }
        req.session.admin = {
          id: admin.adminid,
          email: admin.email,
        };
        req.session.isLoggedIn = true;
        return req.session.save((err) => {
          if (err) {
            req.flash('error', 'Error in saving session');
            return next(err);
          }
          return res.redirect('/profile');
        });
      });
    })(req, res, next);
  };
  exports.profile = (req, res, next) => {
    if (req.session.admin != undefined) {
      // Retrieve admin data from the database
      const connection = require('../db-config');
      connection.query('SELECT * FROM admin WHERE email = ?', [req.session.admin.email], (err, results) => {
        if (err) {
          req.flash('error', 'Error retrieving admin data');
          return next(err);
        }
        const admin = results[0];
        // console.log(results)
        return res.render('admin/profile', { admin: admin });
      });
    } else {
      return res.render('admin/home', { admin: "" });
    }
  }
  exports.updatePassword = (req, res, next) => {
      const connection = require('../db-config');
      const bcrypt = require('bcrypt');
      const validator = require('validator');
      
      // Check if the admin wants to update their password
      if (req.body.updatePassword) {
          const { currentPassword, newPassword } = req.body;
          
          if (!currentPassword || !newPassword) {
              req.flash('error', 'All fields are required*');
              return res.redirect('/profile');
            }
            // Validate the new password
            if (!validator.isStrongPassword(newPassword)) {
                req.flash('error', 'Password is weak. Try a strong password');
                return res.redirect('/profile');
            }
      // Check if the new password is same as the current password
      if (currentPassword === newPassword) {
        req.flash('error', 'New password should not be same as current password');
        return res.redirect('/profile');
    }
  
    // Retrieve the current admin's password from the database
    connection.query('SELECT password FROM admin WHERE email = ?', [req.session.admin.email], (err, results) => {
        if (err) {
            req.flash('error', 'Error retrieving admin data');
            return next(err);
        }
        
        const admin = results[0];
        
        // Compare the admin's input for the current password with the password in the database
        if (bcrypt.compareSync(currentPassword, admin.password)) {
          // The current password matches, so update the admin's password in the database
          const hash = bcrypt.hashSync(newPassword, 10);
          connection.query('UPDATE admin SET password = ? WHERE email = ?', [hash, req.session.admin.email], (err, results) => {
              if (err) {
                  req.flash('error', 'Error updating password');
                  return next(err);
                }
                
                // Log out the admin after the password is updated
                req.session.destroy((err) => {
              if (err) {
                req.flash('error', 'Error logging out admin');
                return next(err);
            }
            
            // Redirect the admin to the login page with a success message
            return res.redirect('/login');
        });
    });
} else {
    // The current password is incorrect, so redirect the admin to the profile page with an error message
    req.flash('error', 'Current password is incorrect');
    return res.redirect('/profile');
}
});
} else {
    // If the admin did not submit an update request, redirect them to the profile page with an error message
    req.flash('error', 'Invalid update request');
    return res.redirect('/profile');
}
};
exports.getBookingdetails = (req, res, next) => {
    const moment = require('moment');
    const connection = require('../db-config');
  
    const query = `SELECT * FROM bookings`;
    connection.query(query, (error, results) => {
      if (error) throw error;
  
      // Use moment to format checkin and checkout dates
      results.forEach((booking) => {
        booking.checkin = moment(booking.checkin).format('DD/MM/YYYY');
        booking.checkout = moment(booking.checkout).format('DD/MM/YYYY');
      });
  
      return res.render('admin/bookingdetails', { bookings: results, admin: req.session.admin });
    });
  };

  exports.updatestatus = (req, res, next) => {
    const connection = require('../db-config');
    const validator = require('validator');
  
    if (req.body.updateDetails) {
      const { bookingid, bookingstatus, roomnumber } = req.body;
  
      // Validate input
      if (!bookingid || !bookingstatus || !roomnumber) {
        req.flash('error', 'Booking ID, booking status, and room number are required');
        return res.redirect('/bookingdetails');
      }
  
      if (!['confirmed', 'pending', 'cancelled'].includes(bookingstatus.toLowerCase())) {
        req.flash('error', 'Invalid booking status');
        return res.redirect('/bookingdetails');
      }
  
      // Update booking status and room number
      connection.query('UPDATE bookings SET bookingstatus = ?, roomnumber = ? WHERE bookingid = ?', [bookingstatus, roomnumber, bookingid], (err, results) => {
        if (err) {
          req.flash('error', 'Error updating booking status and room number');
          return next(err);
        }
  
        req.flash('success', 'Booking status and room number updated successfully');
        return res.redirect('/bookingdetails');
      });
    }
  };
  exports.getRooms = (req, res, next) => {
    const connection = require('../db-config');
    connection.query('SELECT * FROM hotelrooms', (error, results) => {
      if (error) throw error;
      if (req.session.admin) {
        return res.render('admin/roomdetails', { rooms: results, admin: req.session.admin });
      } else {
        return res.render('admin/roomdetails', { rooms: results, admin: null });
      }
    });
  }; 
  exports.updateaction = (req, res, next) => {
    const connection = require('../db-config');
    const validator = require('validator');
  
    if (req.body.updateAction) {
      const { roomid, action } = req.body;
  
      // Validate input
      if (!roomid || !action) {
        req.flash('error', 'Room ID and Room Action are required');
        return res.redirect('/roomdetails');
      }
  
      if (!['enable', 'disable'].includes(action.toLowerCase())) {
        req.flash('error', 'Invalid Action');
        return res.redirect('/roomdetails');
      }
  
      // Update room status
      connection.query('UPDATE hotelrooms SET action = ? WHERE roomid = ?', [action, roomid], (err, results) => {
        if (err) {
          req.flash('error', 'Error updating Room Action');
          return next(err);
        }
  
        req.flash('success', 'Room Action updated successfully');
        return res.redirect('/roomdetails');
      });
    } else {
      // If req.body.updateAction is not truthy, then just redirect back to the rooms page
      return res.redirect('/roomdetails');
    }
  };
  exports.deleterooms = (req, res, next) => {
    const connection = require('../db-config');
    const validator = require('validator');
  
    if (req.body.deleteRoom) {
      const { roomid } = req.body;
  
      // Validate input
      if (!roomid) {
        req.flash('error', 'Room ID is required');
        return res.redirect('/roomdetails');
      }
  
      // Delete room
      connection.query('DELETE FROM hotelrooms WHERE roomid = ?', [roomid], (err, results) => {
        if (err) {
          req.flash('error', 'Error deleting room');
          return next(err);
        }
  
        req.flash('success', 'Room deleted successfully');
        return res.redirect('/roomdetails');
      });
    } else {
      // If req.body.deleteRoom is not truthy, then just redirect back to the rooms page
      return res.redirect('/roomdetails');
    }
  };
exports.getguest = (req, res, next) => {
    const connection = require('../db-config');
    if (req.session.admin !== undefined) {
      connection.query('SELECT * FROM users', (err, result) => {
        if (err) {
          req.flash('error', 'error in retrieving user data');
          return next(err);
        }
        const users = result;
        return res.render('admin/userdetails', { admin: req.session.admin.email, users: users });
      });
    } else {
      return res.render('admin/userdetails', { admin: ""});
    }
};
exports.getreview = (req, res, next) => {
    const connection = require('../db-config');
    if (req.session.admin !== undefined) {
      connection.query('SELECT * FROM review', (err, result) => {
        if (err) {
          req.flash('error', 'error in retrieving user data');
          return next(err);
        }
        const users = result;
        return res.render('admin/userreview', { admin: req.session.admin.email, users: users });
      });
    } else {
      return res.render('admin/userreview', { admin: ""});
    }
    };
exports.postreview = (req, res, next) => {
      const connection = require('../db-config');
      const validator = require('validator');
    
      if (req.body.updateAction) {
        const { email, action } = req.body;
    
        // Validate input
        if (!email || !action) {
          req.flash('error', 'invalid details');
          return res.redirect('/userreview');
        }
    
        if (!['enable', 'disable'].includes(action.toLowerCase())) {
          req.flash('error', 'Invalid Action');
          return res.redirect('/userreview');
        }
    
        // Update room status
        connection.query('UPDATE review SET action = ? WHERE email = ?', [action, email], (err, results) => {
          if (err) {
            req.flash('error', 'Error updating Review Action');
            return next(err);
          }
    
          req.flash('success', 'Review Action updated successfully');
          return res.redirect('/userreview');
        });
      } else {
        // If req.body.updateAction is not truthy, then just redirect back to the rooms page
        return res.redirect('/userreview');
  }
  }   
    exports.getcontact = (req, res, next) => {
        const connection = require('../db-config');
        if (req.session.admin !== undefined) {
          connection.query('SELECT * FROM contact', (err, result) => {
            if (err) {
              req.flash('error', 'error in retrieving user data');
              return next(err);
            }
            const users = result;
            return res.render('admin/usermessage', { admin: req.session.admin.email, users: users });
          });
        } else {
          return res.render('admin/usermessage', { admin: ""});
   }
   };
exports.getCreateroom = (req, res, next) => {
    if (req.session.admin !== undefined ) {
      return res.render('admin/createroom', { admin: req.session.admin });
    } else {
      return res.render('admin/createroom',{ admin: "" });
    }
  };
  exports.postCreateroom = (req, res, next) => {
    const connection = require('../db-config');
    const validator = require('validator');
  
    if (req.body.createRoom) {
      const { roomname, roomcost, capacity, services, description, image, action } = req.body;
  
      // Validate input
      if (!roomname || !roomcost || !capacity || !services || !description || !image ) {
        req.flash('error', 'All fields are required');
        return res.redirect('/createroom');
      }
  
      if (!validator.isAlpha(roomname, 'en-US', { ignore: ' ' })) {
        req.flash('error', 'Invalid room name.');
        req.flash('roomcost', roomcost);
        req.flash('capacity', capacity);
        req.flash('services', services);
        req.flash('description', description);
        req.flash('image', image);
        return res.redirect('/createroom');
      }
  
      if (!validator.isNumeric(roomcost)) {
        req.flash('error', 'Invalid room cost.');
        req.flash('roomname', roomname);
        req.flash('capacity', capacity);
        req.flash('services', services);
        req.flash('description', description);
        req.flash('image', image);
        return res.redirect('/createroom');
      }
  
      if (!validator.isInt(capacity)) {
        req.flash('error', 'Invalid capacity.');
        req.flash('roomname', roomname);
        req.flash('roomcost', roomcost);
        req.flash('services', services);
        req.flash('description', description);
        req.flash('image', image);
        return res.redirect('/createroom');
      }
  
      if (!validator.isLength(services, { min: 5 })) {
        req.flash('error', 'Services must be at least 5 characters.');
        req.flash('roomname', roomname);
        req.flash('roomcost', roomcost);
        req.flash('capacity', capacity);
        req.flash('description', description);
        req.flash('image', image);
        return res.redirect('/createroom');
      }
  
      if (!validator.isLength(description, { min: 10 })) {
        req.flash('error', 'Description must be at least 10 characters.');
        req.flash('roomname', roomname);
        req.flash('roomcost', roomcost);
        req.flash('capacity', capacity);
        req.flash('services', services);
        req.flash('image', image);
        return res.redirect('/createroom');
      }
  
      if (!validator.isURL(image)) {
        req.flash('error', 'Invalid image URL.');
        req.flash('roomname', roomname);
        req.flash('roomcost', roomcost);
        req.flash('capacity', capacity);
        req.flash('services', services);
        req.flash('description', description);
        return res.redirect('/createroom');
      }
  
      // Insert new room
      connection.query('INSERT INTO hotelrooms (roomname, roomcost, capacity, services, description, image, action) VALUES (?, ?, ?, ?, ?, ?, ?)', [roomname, roomcost, capacity, services, description, image,'enable'], (err, results) => {
        if (err) {
          req.flash('error', 'Error creating new room');
          return next(err);
        }
  
        req.flash('success', 'New room created successfully');
        return res.redirect('/createroom');
      });
    }
  };
  exports.getUpdateRooms = (req, res, next) => {
    const connection = require('../db-config');
    connection.query('SELECT * FROM hotelrooms', (error, results) => {
      if (error) throw error;
      if (req.session.admin) {
        return res.render('admin/updateroom', { rooms: results, admin: req.session.admin });
      } else {
        return res.render('admin/updateroom', { rooms: results, admin: null });
      }
    });
  }; 
  exports.postUpdateRooms = (req, res, next) => {
    const connection = require('../db-config');
    const validator = require('validator');
  
    if (req.body.updateRoom) {
      const { roomid, roomname, roomcost, capacity, services, description, image } = req.body;
  
      // Validate input
      if (!roomname || !roomcost || !capacity || !services || !description || !image ) {
        req.flash('error', 'All fields are required');
        return res.redirect('/updateroom');
      }
  
      if (!validator.isAlpha(roomname, 'en-US', { ignore: ' ' })) {
        req.flash('error', 'Invalid room name.');
        req.flash('roomcost', roomcost);
        req.flash('capacity', capacity);
        req.flash('services', services);
        req.flash('description', description);
        req.flash('image', image);
        return res.redirect('/updateroom');
      }
  
      if (!validator.isNumeric(roomcost)) {
        req.flash('error', 'Invalid room cost.');
        req.flash('roomname', roomname);
        req.flash('capacity', capacity);
        req.flash('services', services);
        req.flash('description', description);
        req.flash('image', image);
        return res.redirect('/updateroom');
      }
  
      if (!validator.isInt(capacity)) {
        req.flash('error', 'Invalid capacity.');
        req.flash('roomname', roomname);
        req.flash('roomcost', roomcost);
        req.flash('services', services);
        req.flash('description', description);
        req.flash('image', image);
        return res.redirect('/updateroom');
      }
  
      if (!validator.isLength(services, { min: 5 })) {
        req.flash('error', 'Services must be at least 5 characters.');
        req.flash('roomname', roomname);
        req.flash('roomcost', roomcost);
        req.flash('capacity', capacity);
        req.flash('description', description);
        req.flash('image', image);
        return res.redirect('/updateroom');
      }
  
      if (!validator.isLength(description, { min: 10 })) {
        req.flash('error', 'Description must be at least 10 characters.');
        req.flash('roomname', roomname);
        req.flash('roomcost', roomcost);
        req.flash('capacity', capacity);
        req.flash('services', services);
        req.flash('image', image);
        return res.redirect('/updateroom');
      }
  
      if (!validator.isURL(image)) {
        req.flash('error', 'Invalid image URL.');
        req.flash('roomname', roomname);
        req.flash('roomcost', roomcost);
        req.flash('capacity', capacity);
        req.flash('services', services);
        req.flash('description', description);
        return res.redirect('/updateroom');
      }
  
      // Update room details
      connection.query('UPDATE hotelrooms SET roomname = ?, roomcost = ?, capacity = ?, services = ?, description = ?, image = ? WHERE roomid = ?', [roomname, roomcost, capacity, services, description, image, roomid], (err, results) => {
        if (err) {
          req.flash('error', 'Error updating room details');
          return next(err);
        }
  
        req.flash('success', 'Room details updated successfully');
        return res.redirect('/updateroom');
      });
    }
  };
  exports.getenquiries = (req, res, next) => {
    const connection = require('../db-config');
    if (req.session.admin !== undefined) {
      const sql = 'SELECT email, roomtype, enquiry FROM roomenquiry';
      connection.query(sql, (err, results) => {
        if (err) {
          req.flash('error', 'error in retrieving room enquiry data');
          return next(err);
        }
        const enquiries = results;
        return res.render('admin/bookingenquiry', { admin: req.session.admin.email, enquiries, messages: req.flash() });
      });
    } else {
      return res.render('admin/bookingenquiry', { admin: "", enquiries: [], messages: req.flash() });
  }
};
exports.getgallery = (req, res, next) => {
  if (req.session.admin !== undefined ) {
    return res.render('admin/usergallery', { admin: req.session.admin });
  } else {
    return res.render('admin/usergallery',{ admin: "" });
  }
};

exports.postgallery = (req, res, next) => {
  const connection = require('../db-config');
  const validator = require('validator');

  if (req.body.image) {
    const image = req.body.image;

    // Validate input
    if (!validator.isURL(image)) {
      req.flash('error', 'Invalid image URL.');
      return res.redirect('/usergallery');
    }

    // Insert new image into gallery table
    connection.query('INSERT INTO gallery (image) VALUES (?)', [image], (err, results) => {
      if (err) {
        req.flash('error', 'Error inserting image into gallery');
        return next(err);
      }

      req.flash('success', 'Image inserted successfully');
      return res.redirect('/usergallery');
    });
  } else {
    // Handle missing image error
    req.flash('error', 'Image URL is required');
    return res.redirect('/usergallery');
  }
};
exports.logout = (req, res, next) => {
  req.session.destroy((err) => {
    if (err) {
      return next(err);
    }
    res.redirect('/');
  });
};

      