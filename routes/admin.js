const express = require('express');
const router = express.Router();
const adminController = require('../controllers/admin');


// Home page
router.get('/', adminController.getHome);
router.get('/login', adminController.getLogin);
router.post('/login', adminController.postLogin);
router.get('/register', adminController.getRegister);
router.post('/register', adminController.postRegister);
router.get('/profile', adminController.profile);
router.post('/profile/update-password', adminController.updatePassword);
router.get('/logout', adminController.logout);
router.get('/bookingdetails', adminController.getBookingdetails);
router.post('/update-booking-status', adminController.updatestatus);
router.get('/roomdetails', adminController.getRooms);
router.post('/updateaction', adminController.updateaction);
router.post('/deleterooms', adminController.deleterooms);
router.get('/userdetails', adminController.getguest);
router.get('/userreview', adminController.getreview);
router.post('/updatereview', adminController.postreview);
router.get('/usermessage', adminController.getcontact);
router.get('/createroom', adminController.getCreateroom);
router.post('/createroom', adminController.postCreateroom);
router.get('/updateroom', adminController.getUpdateRooms);
router.post('/updateroom', adminController.postUpdateRooms);
router.get('/bookingenquiry', adminController.getenquiries);
router.get('/usergallery', adminController.getgallery);
router.post('/usergallery', adminController.postgallery);


module.exports = router;