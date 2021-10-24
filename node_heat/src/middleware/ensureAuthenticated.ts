import { Request, Response, NextFunction } from "express";
import { verify } from "jsonwebtoken";

interface IPayload {
    sub: string;
}

export function ensureAuthenticate(
    request: Request,
    response: Response,
    next: NextFunction
) {
    const authToken = request.headers.authorization;

    if(!authToken) {
        return response.status(401).json({
            errorCode: "token.invalid"
        });
    }

    // Bearer 5656565fd6d5s6sd5sd6f5sd6
    // [0] Bearer
    // [1] 5656565fd6d5s6sd5sd6f5sd6
    const [, token] = authToken.split(" ")

    try {
        const {sub} = verify(token, process.env.JWT_SECRET) as IPayload

        request.user_id = sub;

        return next();
        
    } catch(err) {
        return response.status(401).json({errorCode: "token.expired"})
    }

}