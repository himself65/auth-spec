import express from "express";
import { oauth } from "./oauth.js";
import { magicLink } from "./magic-link.js";
import { passwordReset } from "./password-reset.js";
import { twoFactor } from "./two-factor.js";

const app = express();
app.use(express.json());
app.use(oauth);
app.use(magicLink);
app.use(passwordReset);
app.use(twoFactor);

app.listen(Number(process.env.PORT ?? 3000));
