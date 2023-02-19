const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    data: { type: [mongoose.Schema.Types.Mixed], default: [] },
    totalRate: { type: Number, default: 0 },
    previousRate: { type: Number, default: 0 }
});

module.exports = mongoose.model('User', userSchema);