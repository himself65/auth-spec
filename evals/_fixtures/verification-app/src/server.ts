import express from "express";
import { oauth } from "./oauth.js";

const app = express();
app.use(express.json());
app.use(oauth);

app.listen(Number(process.env.PORT ?? 3000));
