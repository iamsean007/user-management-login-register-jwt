import mongoose, { Document, Schema } from 'mongoose';
import { IUser } from './User';

export interface IToken extends Document {
    refreshToken: string;
    user: IUser['_id'];
}

const TokenSchema: Schema = new Schema({
    refreshToken: { type: String, required: true },
    user: { type: Schema.Types.ObjectId, required: true, ref: 'User' },
});

const Token = mongoose.model<IToken>('Token', TokenSchema);
export default Token;
