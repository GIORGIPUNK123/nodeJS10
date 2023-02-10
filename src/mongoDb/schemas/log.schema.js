const mongoose = require('mongoose');

const Log = new mongoose.Schema({
  actionType: String,
  changedField: String,
  previousValue: String,
  currentValue: String,
  userId: Number,
  
  createdAt: {
    type: Date,
    default: new Date(),
  },

});

module.exports = mongoose.model('logs', Log);