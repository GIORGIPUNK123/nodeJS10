const mongoose = require('mongoose');

const url = `mongodb+srv://root:${process.env.MONGO_DB_PASSOWRD}@digitaledu.5sn11nm.mongodb.net/?retryWrites=true&w=majority`;

(async() => {
  try{
    await mongoose.connect(url);
    console.log('mongoose db connected successfully');
  } catch(e) {
    console.log('mongoose db error', e);
  }
})();


module.exports = mongoose;
